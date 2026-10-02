"""Policy tests for Section 4: the supplied (bad) artefacts must fail, the corrected ones must pass,
and breaking any single control in a corrected artefact must be caught.

Run with: python3 -m unittest discover -s tests -p 'test_policies.py' -v
Needs Docker. The scanners are the same pinned images the pipeline uses.
"""
import filecmp
import functools
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

TRIVY_IMAGE = os.environ.get(
    "TRIVY_IMAGE",
    "ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa")  # 0.75.0
KYVERNO_IMAGE = os.environ.get(
    "KYVERNO_IMAGE",
    "ghcr.io/kyverno/kyverno-cli@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a")  # v1.19.1

# The same flags as the IaC step in .github/workflows/security-gates.yml.
TRIVY_CONFIG_FLAGS = [
    "--severity", "HIGH,CRITICAL",
    "--raw-config-scanners", "terraform",
    "--misconfig-scanners", "azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,json",
    "--config-check", "/repo/policies/terraform",
    "--config-check", "/repo/policies/iam",
    "--check-namespaces", "user",
]

# Enforced (Deny) in the accounts-api namespace from day one.
KUBERNETES_POLICIES = [
    "disallow-host-namespaces", "disallow-host-path", "require-hardened-containers",
    "require-image-digest", "disallow-secrets-in-env", "restrict-rbac",
]
# Audit-only for every other tenant namespace, paired with the enforced policy they mirror.
AUDIT_POLICIES = {
    "audit-cluster-host-namespaces": "disallow-host-namespaces",
    "audit-cluster-host-path": "disallow-host-path",
}

HAVE_DOCKER = shutil.which("docker") is not None and subprocess.run(
    ["docker", "info"], capture_output=True).returncode == 0
# CI sets REQUIRE_POLICY_TESTS=1 so that a missing Docker daemon fails instead of skipping.
if not HAVE_DOCKER and os.environ.get("REQUIRE_POLICY_TESTS") == "1":
    raise RuntimeError("Docker is required for the policy tests")


def docker(image, args, workdir):
    command = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "-e", "HOME=/tmp", "-e", "TRIVY_CACHE_DIR=/tmp/trivy",
               "-v", f"{ROOT}:/repo:ro", "-v", f"{workdir}:/work", "-w", "/work", image, *args]
    return subprocess.run(command, capture_output=True, text=True)


def read(path):
    with open(path) as f:
        return f.read()


def mutate(text, replacements):
    """Apply (old, new) replacements; each old string must be present exactly once."""
    for old, new in replacements:
        assert text.count(old) == 1, f"expected exactly one occurrence of {old!r}"
        text = text.replace(old, new)
    return text


def write(directory, name, text):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, name), "w") as f:
        f.write(text)


# ------------------------------------------------------------ Kubernetes (Kyverno)

def kyverno_apply(*manifests):
    """Apply every policy to the given manifest texts. Returns (exit code, output)."""
    with tempfile.TemporaryDirectory() as work:
        args = ["apply", "/repo/policies/kubernetes"]
        for i, text in enumerate(manifests):
            write(work, f"resource-{i}.yaml", text)
            args += ["--resource", f"/work/resource-{i}.yaml"]
        done = docker(KYVERNO_IMAGE, args, work)
    return done.returncode, done.stdout + done.stderr


# One broken control at a time, applied to the corrected manifest: (name, replacements, policy, message).
KUBERNETES_MUTATIONS = [
    ("hostNetwork", [("      serviceAccountName: accounts-api\n", "      serviceAccountName: accounts-api\n      hostNetwork: true\n")],
     "disallow-host-namespaces", "hostNetwork"),
    ("hostPath", [("          emptyDir:\n            sizeLimit: 64Mi", "          hostPath:\n            path: /var/log")],
     "disallow-host-path", "hostPath"),
    ("runAsUser 0", [("        runAsUser: 10001", "        runAsUser: 0")],
     "require-hardened-containers", "must not run as root"),
    ("runAsNonRoot missing", [("            runAsNonRoot: true\n", "")],
     "require-hardened-containers", "must not run as root"),
    ("privileged", [("privileged: false", "privileged: true")],
     "require-hardened-containers", "Privileged"),
    ("allowPrivilegeEscalation", [("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true")],
     "require-hardened-containers", "allowPrivilegeEscalation"),
    ("readOnlyRootFilesystem", [("readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false")],
     "require-hardened-containers", "readOnlyRootFilesystem"),
    ("capabilities", [('drop: ["ALL"]', 'drop: ["NET_RAW"]')],
     "require-hardened-containers", "capabilities"),
    ("seccomp", [("type: RuntimeDefault", "type: Unconfined")],
     "require-hardened-containers", "seccompProfile"),
    ("image tag", [("@sha256:" + "0" * 64, ":latest")],
     "require-image-digest", "digest"),
    ("secret in env", [("              value: ap-south-1", "              valueFrom:\n                secretKeyRef:\n                  name: accounts-api-env\n                  key: region")],
     "disallow-secrets-in-env", "environment variables"),
]

ROLE_MUTATIONS = [
    ("wildcard verb", [('verbs: ["get"]', 'verbs: ["*"]')], "'*' is not allowed"),
    ("unnamed configmaps", [('    resourceNames: ["accounts-api-config"]\n', "")], "must name the objects"),
    ("all secrets", [('resources: ["configmaps"]', 'resources: ["secrets"]'), ('    resourceNames: ["accounts-api-config"]\n', "")],
     "must name the objects"),
    ("write to named secret", [('resources: ["configmaps"]', 'resources: ["secrets"]'), ('verbs: ["get"]', 'verbs: ["get", "update"]')],
     "limited to the verb get"),
    ("create pods", [('resources: ["configmaps"]', 'resources: ["pods"]'), ('verbs: ["get"]', 'verbs: ["create"]')],
     "must not create, change or delete pods"),
]


@unittest.skipUnless(HAVE_DOCKER, "Docker is not available")
class KubernetesPolicies(unittest.TestCase):
    bad = read(os.path.join(FIXTURES, "kubernetes", "bad.yaml"))
    good = read(os.path.join(FIXTURES, "kubernetes", "good.yaml"))
    good_role = read(os.path.join(FIXTURES, "kubernetes", "good-role.yaml"))

    def test_bad_manifest_is_rejected_by_every_policy(self):
        code, output = kyverno_apply(self.bad)
        self.assertNotEqual(code, 0, output)
        for policy in KUBERNETES_POLICIES:
            self.assertIn(f"policy {policy} -> resource", output)
        self.assertIn("pass: 0, fail: 6", output)

    def test_good_manifest_and_least_privilege_role_pass(self):
        code, output = kyverno_apply(self.good, self.good_role)
        self.assertEqual(code, 0, output)
        self.assertIn("pass: 6, fail: 0", output)

    def test_fixed_manifest_is_the_good_fixture(self):
        self.assertTrue(filecmp.cmp(os.path.join(ROOT, "kubernetes", "accounts-api.yaml"),
                                    os.path.join(FIXTURES, "kubernetes", "good.yaml"), shallow=False))

    def test_every_manifest_in_the_kubernetes_directory_passes(self):
        directory = os.path.join(ROOT, "kubernetes")
        manifests = [read(os.path.join(directory, f)) for f in sorted(os.listdir(directory)) if f.endswith(".yaml")]
        code, output = kyverno_apply(*manifests)
        self.assertEqual(code, 0, output)

    def test_other_tenants_are_audited_not_blocked(self):
        # The same bad manifest in another team's namespace: reported by the two audit policies
        # only, because every enforced policy is scoped to accounts-api. The CLI evaluates rules;
        # that these two do not block is their validationActions, checked in AdmissionModes.
        code, output = kyverno_apply(self.bad.replace("namespace: accounts-api", "namespace: team-b"))
        for policy in AUDIT_POLICIES:
            self.assertIn(f"policy {policy} -> resource team-b/Deployment/accounts-api failed", output)
        for policy in KUBERNETES_POLICIES:
            self.assertNotIn(f"policy {policy} ->", output)

    def test_breaking_any_one_workload_control_is_rejected(self):
        for name, replacements, policy, message in KUBERNETES_MUTATIONS:
            with self.subTest(control=name):
                code, output = kyverno_apply(mutate(self.good, replacements))
                self.assertNotEqual(code, 0, output)
                self.assertIn(f"policy {policy} -> resource", output)
                self.assertIn(message, output)

    def test_breaking_any_one_rbac_control_is_rejected(self):
        for name, replacements, message in ROLE_MUTATIONS:
            with self.subTest(control=name):
                code, output = kyverno_apply(mutate(self.good_role, replacements))
                self.assertNotEqual(code, 0, output)
                self.assertIn("policy restrict-rbac -> resource", output)
                self.assertIn(message, output)


class AdmissionModes(unittest.TestCase):
    """The mode of every admission policy is explicit and matches policies/kubernetes/README.md."""

    @staticmethod
    def policy(name):
        import yaml
        with open(os.path.join(ROOT, "policies", "kubernetes", f"{name}.yaml")) as f:
            return yaml.safe_load(f)

    def test_every_policy_file_is_classified(self):
        directory = os.path.join(ROOT, "policies", "kubernetes")
        files = {f[:-5] for f in os.listdir(directory) if f.endswith(".yaml")}
        self.assertEqual(files, set(KUBERNETES_POLICIES) | set(AUDIT_POLICIES))

    def test_accounts_api_policies_enforce(self):
        for name in KUBERNETES_POLICIES:
            with self.subTest(policy=name):
                policy = self.policy(name)
                self.assertEqual(policy["spec"]["validationActions"], ["Deny"])
                self.assertEqual(policy["metadata"]["annotations"]["accounts-api.mal/mode"], "enforce")
                self.assertIn("== 'accounts-api'", policy["spec"]["matchConditions"][0]["expression"])

    def test_cluster_wide_policies_audit_and_skip_accounts_api(self):
        for name in AUDIT_POLICIES:
            with self.subTest(policy=name):
                policy = self.policy(name)
                self.assertEqual(policy["spec"]["validationActions"], ["Audit"])
                self.assertEqual(policy["metadata"]["annotations"]["accounts-api.mal/mode"], "audit")
                self.assertIn("accounts-api", policy["spec"]["matchConditions"][0]["expression"])
                self.assertIn("kube-system", policy["spec"]["matchConditions"][0]["expression"])

    def test_audit_policies_check_exactly_what_the_enforced_ones_check(self):
        for audit, enforce in AUDIT_POLICIES.items():
            with self.subTest(policy=audit):
                self.assertEqual(self.policy(audit)["spec"]["validations"], self.policy(enforce)["spec"]["validations"])


# --------------------------------------------------- Terraform and IAM (Trivy)

# One broken control at a time, applied to the corrected Terraform: (directory, replacements, expected check IDs).
DB_INGRESS_SOURCE = "referenced_security_group_id = var.accounts_api_pod_security_group_id"

TERRAFORM_MUTATIONS = [
    ("public-ingress", [(DB_INGRESS_SOURCE, 'cidr_ipv4                    = "0.0.0.0/0"')], "ACCT-TF-001"),
    ("public-ingress-ipv6", [(DB_INGRESS_SOURCE, 'cidr_ipv6                    = "::/0"')], "ACCT-TF-001"),
    ("public-ingress-port-range", [(DB_INGRESS_SOURCE, 'cidr_ipv4                    = "0.0.0.0/0"'),
                                   ("from_port                    = 5432", "from_port                    = 5000"),
                                   ("to_port                      = 5432", "to_port                      = 6000")], "ACCT-TF-001"),
    ("public-ingress-all-protocols", [(DB_INGRESS_SOURCE, 'cidr_ipv4                    = "0.0.0.0/0"'),
                                      ('ip_protocol                  = "tcp"', 'ip_protocol                  = "-1"'),
                                      ("  from_port                    = 5432\n", ""),
                                      ("  to_port                      = 5432\n", "")],
     # All ports also opens SSH and RDP, which Trivy's built-in check reports as well.
     {"ACCT-TF-001", "AWS-0107"}),
    ("public-rds", [("publicly_accessible = false", "publicly_accessible = true")], "AWS-0180"),
    ("unencrypted", [("storage_encrypted   = true", "storage_encrypted   = false")], "AWS-0080"),
    ("no-backups", [("backup_retention_period = 35", "backup_retention_period = 0")], "ACCT-TF-002"),
    ("no-final-snapshot", [("skip_final_snapshot       = false", "skip_final_snapshot       = true")], "ACCT-TF-003"),
    ("single-region-trail", [("is_multi_region_trail         = true", "is_multi_region_trail         = false")], "ACCT-TF-004"),
    ("no-log-validation", [("enable_log_file_validation    = true", "enable_log_file_validation    = false")], "AWS-0016"),
    ("no-global-events", [("include_global_service_events = true", "include_global_service_events = false")], "ACCT-TF-005"),
]

# The eight supplied Terraform defects, by the check that catches each.
SUPPLIED_TERRAFORM_DEFECTS = {
    "ACCT-TF-001": "PostgreSQL 5432 open to 0.0.0.0/0",
    "AWS-0180": "publicly_accessible = true",
    "AWS-0080": "storage_encrypted = false",
    "ACCT-TF-002": "backup_retention_period = 0",
    "ACCT-TF-003": "skip_final_snapshot = true",
    "ACCT-TF-004": "is_multi_region_trail = false",
    "AWS-0016": "enable_log_file_validation = false",
    "ACCT-TF-005": "include_global_service_events = false",
}

# Legitimate public ingress that ACCT-TF-001 must not reject: HTTPS on the internet-facing ALB.
PUBLIC_ALB_HTTPS = '''
resource "aws_security_group" "alb" {
  provider    = aws.workload
  name        = "accounts-alb"
  description = "Internet-facing ALB"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from the internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}
'''

IAM_MUTATIONS = [
    ("wildcard-resource", [('"Resource": "arn:aws:kinesis:ap-south-1:111122223333:stream/accounts-events"', '"Resource": "*"')]),
    ("wildcard-action", [('"Action": "kms:Decrypt"', '"Action": "kms:*"')]),
    ("not-action", [('"Action": [\n        "secretsmanager:GetSecretValue",\n        "secretsmanager:DescribeSecret"\n      ]',
                     '"NotAction": "iam:DeleteRole"')]),
]


@functools.cache
def trivy_scan():
    """Scan the bad, good and mutated Terraform and IAM fixtures once. Returns {directory: {check IDs}}."""
    good_tf = read(os.path.join(FIXTURES, "terraform", "good", "main.tf"))
    good_iam = read(os.path.join(FIXTURES, "iam", "good.json"))
    with tempfile.TemporaryDirectory() as work:
        write(os.path.join(work, "tf-bad"), "main.tf", read(os.path.join(FIXTURES, "terraform", "bad", "main.tf")))
        write(os.path.join(work, "tf-good"), "main.tf", good_tf)
        for name, replacements, _ in TERRAFORM_MUTATIONS:
            write(os.path.join(work, f"tf-{name}"), "main.tf", mutate(good_tf, replacements))
        write(os.path.join(work, "tf-public-alb-https"), "main.tf", good_tf + PUBLIC_ALB_HTTPS)
        write(os.path.join(work, "iam-bad"), "policy.json", read(os.path.join(FIXTURES, "iam", "bad.json")))
        write(os.path.join(work, "iam-good"), "policy.json", good_iam)
        for name, replacements in IAM_MUTATIONS:
            write(os.path.join(work, f"iam-{name}"), "policy.json", mutate(good_iam, replacements))
        directories = sorted(os.listdir(work))
        done = docker(TRIVY_IMAGE, ["config", "--quiet", "--format", "json", *TRIVY_CONFIG_FLAGS, "."], work)
    if done.returncode != 0:
        raise RuntimeError(f"trivy failed: {done.stderr}")
    found = {d: set() for d in directories}
    for result in json.loads(done.stdout).get("Results") or []:
        directory = result["Target"].split("/")[0]
        for finding in result.get("Misconfigurations") or []:
            if finding.get("Status", "FAIL") == "FAIL":
                found[directory].add(finding["ID"])
    return found


@unittest.skipUnless(HAVE_DOCKER, "Docker is not available")
class TerraformPolicies(unittest.TestCase):
    def test_bad_fixture_is_flagged_for_every_supplied_defect(self):
        for check, defect in SUPPLIED_TERRAFORM_DEFECTS.items():
            with self.subTest(defect=defect):
                self.assertIn(check, trivy_scan()["tf-bad"])

    def test_good_fixture_has_no_blocking_findings(self):
        self.assertEqual(trivy_scan()["tf-good"], set())

    def test_supplied_public_database_rule_is_rejected(self):
        self.assertIn("ACCT-TF-001", trivy_scan()["tf-bad"])

    def test_corrected_database_rule_passes(self):
        self.assertNotIn("ACCT-TF-001", trivy_scan()["tf-good"])

    def test_public_https_on_the_alb_is_not_rejected(self):
        self.assertEqual(trivy_scan()["tf-public-alb-https"], set())

    def test_fixed_terraform_is_the_good_fixture(self):
        self.assertTrue(filecmp.cmp(os.path.join(ROOT, "terraform", "review-remediate.tf"),
                                    os.path.join(FIXTURES, "terraform", "good", "main.tf"), shallow=False))

    def test_breaking_any_one_control_is_flagged(self):
        for name, _, check in TERRAFORM_MUTATIONS:
            with self.subTest(control=name):
                expected = check if isinstance(check, set) else {check}
                self.assertEqual(trivy_scan()[f"tf-{name}"], expected)


@unittest.skipUnless(HAVE_DOCKER, "Docker is not available")
class IamPolicies(unittest.TestCase):
    def test_supplied_policy_is_flagged(self):
        self.assertEqual(trivy_scan()["iam-bad"], {"ACCT-IAM-001"})

    def test_rewritten_policy_has_no_findings(self):
        self.assertEqual(trivy_scan()["iam-good"], set())

    def test_rewritten_policy_is_the_good_fixture(self):
        self.assertTrue(filecmp.cmp(os.path.join(ROOT, "iam", "accounts-api-pod-policy.json"),
                                    os.path.join(FIXTURES, "iam", "good.json"), shallow=False))

    def test_reintroducing_any_wildcard_is_flagged(self):
        for name, _ in IAM_MUTATIONS:
            with self.subTest(control=name):
                self.assertEqual(trivy_scan()[f"iam-{name}"], {"ACCT-IAM-001"})


if __name__ == "__main__":
    unittest.main()
