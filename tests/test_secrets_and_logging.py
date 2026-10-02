"""Section 6 tests: secrets reach the pod only as read-only files from Secrets Manager, no
credential is committed, rotation is scheduled, and the log policy's patterns behave as documented.

Run with: python3 -m unittest discover -s tests -p 'test_secrets_and_logging.py' -v
"""
import json
import os
import re
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SECRET_NAMES = {"accounts-api/db-credentials", "accounts-api/kyc-api-key"}


def read(*parts):
    with open(os.path.join(ROOT, *parts)) as f:
        return f.read()


def documents(*parts):
    return [d for d in yaml.safe_load_all(read(*parts)) if d]


def kubernetes_documents():
    directory = os.path.join(ROOT, "kubernetes")
    found = []
    for folder, _, files in os.walk(directory):
        for name in files:
            if name.endswith(".yaml"):
                found += documents(os.path.relpath(os.path.join(folder, name), ROOT))
    return found


class SecretsDelivery(unittest.TestCase):
    provider_class = documents("kubernetes", "accounts-api-secrets.yaml")[0]
    deployment = [d for d in documents("kubernetes", "accounts-api.yaml") if d["kind"] == "Deployment"][0]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]

    def test_provider_class_uses_secrets_manager_with_the_pod_identity(self):
        spec = self.provider_class["spec"]
        self.assertEqual(self.provider_class["kind"], "SecretProviderClass")
        self.assertEqual(self.provider_class["metadata"]["namespace"], "accounts-api")
        self.assertEqual(spec["provider"], "aws")
        self.assertEqual(spec["parameters"]["usePodIdentity"], "true")
        objects = yaml.safe_load(spec["parameters"]["objects"])
        self.assertEqual({o["objectName"] for o in objects}, SECRET_NAMES)
        self.assertTrue(all(o["objectType"] == "secretsmanager" for o in objects))

    def test_nothing_is_synced_into_a_kubernetes_secret(self):
        self.assertNotIn("secretObjects", self.provider_class["spec"])
        self.assertEqual([d for d in kubernetes_documents() if d.get("kind") == "Secret"], [])

    def test_secrets_are_mounted_read_only_from_the_csi_driver(self):
        volume = [v for v in self.pod["volumes"] if v["name"] == "secrets"][0]
        self.assertEqual(volume["csi"]["driver"], "secrets-store.csi.k8s.io")
        self.assertTrue(volume["csi"]["readOnly"])
        self.assertEqual(volume["csi"]["volumeAttributes"]["secretProviderClass"],
                         self.provider_class["metadata"]["name"])
        mount = [m for m in self.container["volumeMounts"] if m["name"] == "secrets"][0]
        self.assertTrue(mount["readOnly"])

    def test_environment_holds_file_paths_and_no_secret(self):
        self.assertNotIn("envFrom", self.container)
        for variable in self.container["env"]:
            with self.subTest(variable=variable["name"]):
                self.assertNotIn("valueFrom", variable)
                self.assertNotRegex(variable["name"], r"(?i)password|secret_value|api_key$|token")
        files = {v["name"]: v["value"] for v in self.container["env"] if v["name"].endswith("_FILE")}
        self.assertEqual(files, {"ACCOUNTS_API_DB_CREDENTIALS_FILE": "/mnt/secrets/db-credentials.json",
                                 "ACCOUNTS_API_KYC_API_KEY_FILE": "/mnt/secrets/kyc-api-key"})

    def test_pod_identity_may_read_exactly_the_mounted_secrets(self):
        policy = json.loads(read("iam", "accounts-api-pod-policy.json"))
        statement = [s for s in policy["Statement"] if s["Sid"] == "ReadOwnSecretsOnly"][0]
        self.assertEqual(set(statement["Action"]), {"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"})
        granted = {re.sub(r"-\?{6}$", "", arn.split(":secret:")[1]) for arn in statement["Resource"]}
        self.assertEqual(granted, SECRET_NAMES)


class CsiDriverRotation(unittest.TestCase):
    """The driver does not refresh mounted secrets unless auto-rotation is switched on."""
    values = yaml.safe_load(read("kubernetes", "secrets-store-csi-driver", "values.yaml"))

    def test_auto_rotation_is_enabled_with_a_two_minute_poll(self):
        self.assertIs(self.values["enableSecretRotation"], True)
        self.assertEqual(self.values["rotationPollInterval"], "2m")

    def test_sync_to_kubernetes_secrets_is_disabled(self):
        self.assertIs(self.values["syncSecret"]["enabled"], False)

    def test_documents_state_the_three_step_path_and_the_non_default(self):
        delivery = read("data-protection", "README.md")
        self.assertIn("The driver does not refresh secrets by default.", delivery)
        self.assertIn("Secrets Manager rotation  ->  CSI reconciler updates the mounted file  ->  "
                      "application re-reads the file, or the pods are rolled", delivery)


class HonestStatus(unittest.TestCase):
    """Wording that must not overstate what this repository implements."""
    STATUS = ("The Terraform configures the secret and rotation schedule; the production rotation Lambda "
              "implementing the alternating-user strategy is specified but not deployed/tested in this assessment.")
    TLS = ("The accounts-api database client is required to use TLS. Production should also enable the RDS "
           "PostgreSQL `rds.force_ssl` parameter so non-TLS clients are rejected.")

    def test_rotation_function_is_described_as_specified_not_deployed(self):
        self.assertIn(self.STATUS, read("data-protection", "rotation.md"))
        self.assertIn(self.STATUS, read("data-protection", "README.md"))
        self.assertNotIn("aws_lambda_function", read("terraform", "secrets.tf"))

    def test_tls_is_stated_as_a_client_requirement_not_server_enforcement(self):
        self.assertIn(self.TLS, read("data-protection", "log-redaction.md"))
        self.assertIn(self.TLS, read("data-protection", "README.md"))
        for name in sorted(os.listdir(os.path.join(ROOT, "terraform"))):
            if name.endswith(".tf"):
                self.assertNotIn("rds.force_ssl", read("terraform", name))


class NoPlaintextCredentials(unittest.TestCase):
    terraform = {name: read("terraform", name) for name in sorted(os.listdir(os.path.join(ROOT, "terraform")))
                 if name.endswith(".tf")}

    def test_terraform_never_sets_a_secret_value(self):
        for name, text in self.terraform.items():
            with self.subTest(file=name):
                self.assertNotIn('resource "aws_secretsmanager_secret_version"', text)
                self.assertNotRegex(text, r'(?m)^\s*(password|secret_string)\s*=')

    def test_database_secret_rotates_every_30_days(self):
        self.assertRegex(self.terraform["secrets.tf"], r'automatically_after_days\s*=\s*30\b')

    def test_secrets_use_the_customer_managed_key(self):
        text = self.terraform["secrets.tf"]
        self.assertEqual(len(re.findall(r'resource "aws_secretsmanager_secret" ', text)), 2)
        self.assertEqual(len(re.findall(r'kms_key_id\s*=\s*aws_kms_key\.accounts_api_secrets\.arn', text)), 2)

    def test_key_administrator_cannot_decrypt(self):
        text = self.terraform["secrets.tf"]
        admin = text[text.index("AdministerButNeverDecrypt"):text.index("WorkloadDecryptsThroughSecretsManagerOnly")]
        self.assertNotIn("kms:Decrypt", admin)
        self.assertNotIn("kms:*", text)


class RotationTargets(unittest.TestCase):
    rotation = read("data-protection", "rotation.md")

    def test_every_credential_has_an_interval_and_an_emergency_target(self):
        self.assertIn("| Database credential | Secrets Manager, `accounts-api/db-credentials` | 30 days, scheduled | **15 minutes or less** |", self.rotation)
        self.assertRegex(self.rotation, r"\| KYC provider API key \|.*\| 90 days.*\| \*\*30 minutes or less\*\*")
        self.assertIn("accounts-api has no long-lived AWS credential", self.rotation)

    def test_emergency_step_budgets_fit_inside_the_database_target(self):
        section = self.rotation[self.rotation.index("**Emergency rotation: target 15 minutes or less.**"):self.rotation.index("## B.")]
        budgets = [int(n) for n in re.findall(r"\| (\d+) min \|", section)]
        self.assertEqual(len(budgets), 4)
        self.assertLessEqual(sum(budgets), 15)


class LogPolicy(unittest.TestCase):
    policy = yaml.safe_load(read("data-protection", "log-policy.yaml"))
    patterns = {p["name"]: re.compile(p["regex"]) for p in policy["pipeline_patterns"]}

    # A compliant event: only allowlisted fields, as stage 1 should emit it.
    GOOD_EVENT = {
        "timestamp": "2026-10-02T13:45:10.123Z", "level": "info", "event": "kyc_check_completed",
        "request_id": "550e8400-e29b-41d4-a716-446655440000", "route": "/accounts/{id}/kyc", "method": "POST",
        "status": 200, "latency_ms": 182, "service": "accounts-api", "version": "1.42.0",
        "image_digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "pod": "accounts-api-7d9f8c6b5-x2x9p", "namespace": "accounts-api",
        "subject_ref": "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a",
    }
    # What a careless handler would log.
    BAD_EVENT = {
        "timestamp": "2026-10-02T13:45:10.123Z", "level": "info", "message": "KYC ok for Jane Doe",
        "email": "jane.doe@example.com", "headers": {"Authorization": "Bearer abcdefghijklmnop"},
        "customer_id": "C-1029384", "query": "iban=GB29NWBK60161331926819",
    }

    def not_allowed(self, event):
        return sorted(set(event) - set(self.policy["allowed_fields"]))

    def forbidden(self, event):
        keys = set()
        def walk(value):
            if isinstance(value, dict):
                for key, inner in value.items():
                    keys.add(key.lower())
                    walk(inner)
        walk(event)
        return sorted(keys & {k.lower() for k in self.policy["forbidden_keys"]})

    def matches(self, event):
        return sorted({name for value in event.values() if isinstance(value, str)
                       for name, pattern in self.patterns.items() if pattern.search(value)})

    def test_allowlist_and_forbidden_list_do_not_overlap(self):
        self.assertEqual(set(self.policy["allowed_fields"]) & set(self.policy["forbidden_keys"]), set())

    def test_compliant_event_passes_every_stage(self):
        self.assertEqual(self.not_allowed(self.GOOD_EVENT), [])
        self.assertEqual(self.forbidden(self.GOOD_EVENT), [])
        self.assertEqual(self.matches(self.GOOD_EVENT), [], "a pattern masks a safe operational value")

    def test_careless_event_is_caught(self):
        self.assertEqual(self.not_allowed(self.BAD_EVENT), ["customer_id", "email", "headers", "message", "query"])
        self.assertEqual(self.forbidden(self.BAD_EVENT), ["authorization", "customer_id", "email", "headers", "query"])
        self.assertEqual(self.matches(self.BAD_EVENT), ["email", "iban"])

    def test_each_pattern_matches_its_examples_and_nothing_else_listed(self):
        for entry in self.policy["pipeline_patterns"]:
            pattern = self.patterns[entry["name"]]
            for sample in entry["match"]:
                with self.subTest(pattern=entry["name"], should_match=sample):
                    self.assertIsNotNone(pattern.search(sample))
            for sample in entry["no_match"]:
                with self.subTest(pattern=entry["name"], should_not_match=sample):
                    self.assertIsNone(pattern.search(sample))

    def test_jwt_pattern_matches_a_realistic_token(self):
        # Assembled from parts so the full token never appears as a literal in the repository.
        token = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"])
        self.assertIsNotNone(self.patterns["jwt"].search(f"token={token}"))

    def test_patterns_avoid_lookarounds(self):
        for name, pattern in self.patterns.items():
            with self.subTest(pattern=name):
                self.assertNotRegex(pattern.pattern, r"\(\?[=!<]")

    def test_specification_carries_the_encryption_statement(self):
        spec = read("data-protection", "log-redaction.md")
        self.assertIn("encrypted at rest with customer-managed AWS KMS keys, with key administration separated "
                      "from workload use; TLS protects data in transit.", spec)
        self.assertIn("does not protect data from an authorised or compromised running accounts-api process", spec)


if __name__ == "__main__":
    unittest.main()
