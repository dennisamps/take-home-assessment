"""Section 5 tests: the Falco rule is valid and tightly scoped, and the egress control allows
only what the design says it allows.

Run with: python3 -m unittest discover -s tests -p 'test_runtime_and_egress.py' -v
The Falco and Squid checks need Docker. EGRESS_LIVE_TEST=1 also starts the proxy and sends
real requests through it (needs internet access).
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FALCO_RULES = os.path.join(ROOT, "runtime", "falco", "accounts-api-rules.yaml")
SQUID_CONF = os.path.join(ROOT, "kubernetes", "egress-proxy", "squid.conf")
NETWORK_POLICY = os.path.join(ROOT, "kubernetes", "accounts-api-network-policy.yaml")

FALCO_IMAGE = os.environ.get(
    "FALCO_IMAGE",
    "falcosecurity/falco@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6")  # 0.45.0
SQUID_IMAGE = os.environ.get(
    "SQUID_IMAGE",
    "ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029")  # Squid 6.13
CURL_IMAGE = os.environ.get(
    "CURL_IMAGE",
    "curlimages/curl@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777")

KYC_HOSTNAME = "api.kyc-provider.example"

HAVE_DOCKER = shutil.which("docker") is not None and subprocess.run(
    ["docker", "info"], capture_output=True).returncode == 0
if not HAVE_DOCKER and os.environ.get("REQUIRE_POLICY_TESTS") == "1":
    raise RuntimeError("Docker is required for the runtime and egress tests")


def run(*command):
    return subprocess.run(command, capture_output=True, text=True)


def load_all(path):
    with open(path) as f:
        return [doc for doc in yaml.safe_load_all(f) if doc]


# ------------------------------------------------------------------ Falco rule

class FalcoRule(unittest.TestCase):
    items = load_all(FALCO_RULES)[0]

    def named(self, kind, name=None):
        found = [i for i in self.items if kind in i and (name is None or i[kind] == name)]
        return found[0] if name else found

    def test_there_is_exactly_one_rule(self):
        self.assertEqual(len(self.named("rule")), 1)

    def test_rule_is_scoped_to_the_accounts_api_container(self):
        rule = self.named("rule")[0]
        self.assertIn("accounts_api_container", rule["condition"])
        scope = self.named("macro", "accounts_api_container")["condition"]
        self.assertIn('k8s.ns.name = "accounts-api"', scope)
        self.assertIn('container.name = "accounts-api"', scope)

    def test_rule_pages_and_carries_the_fields_a_responder_needs(self):
        rule = self.named("rule")[0]
        self.assertEqual(rule["priority"], "CRITICAL")
        self.assertIn("accounts-api", rule["tags"])
        for field in ("%proc.cmdline", "%proc.exepath", "%proc.pname", "%user.uid", "%k8s.ns.name",
                      "%k8s.pod.name", "%container.id", "%container.image.digest"):
            self.assertIn(field, rule["output"])

    @unittest.skipUnless(HAVE_DOCKER, "Docker is not available")
    def test_falco_accepts_the_rule_file(self):
        done = run("docker", "run", "--rm", "-v", f"{FALCO_RULES}:/rules/accounts-api-rules.yaml:ro",
                   FALCO_IMAGE, "falco", "--validate", "/rules/accounts-api-rules.yaml")
        output = done.stdout + done.stderr
        self.assertEqual(done.returncode, 0, output)
        self.assertIn("accounts-api-rules.yaml: Ok", output)
        self.assertNotIn("Warning", output)


# -------------------------------------------------------------- NetworkPolicy

ALL_NETWORK_POLICIES = {p["metadata"]["name"]: p for p in load_all(NETWORK_POLICY)}


class EgressNetworkPolicy(unittest.TestCase):
    policies = {n: p for n, p in ALL_NETWORK_POLICIES.items() if p["spec"]["policyTypes"] == ["Egress"]}

    # Every destination accounts-api may reach directly. Anything else must go through the proxy.
    ALLOWED_CIDRS = {
        "10.0.20.0/24": 5432,       # RDS subnets
        "10.0.21.0/24": 5432,
        "10.0.30.0/24": 443,        # VPC interface endpoints
        "169.254.170.23/32": 80,    # EKS Pod Identity Agent
    }

    def test_every_policy_is_in_the_accounts_api_namespace_and_has_one_direction(self):
        for name, policy in ALL_NETWORK_POLICIES.items():
            with self.subTest(policy=name):
                self.assertEqual(policy["metadata"]["namespace"], "accounts-api")
                self.assertIn(policy["spec"]["policyTypes"], (["Egress"], ["Ingress"]))

    def test_default_deny_covers_every_pod_and_allows_nothing(self):
        spec = self.policies["default-deny-egress"]["spec"]
        self.assertEqual(spec["podSelector"], {})
        self.assertNotIn("egress", spec)

    def test_allow_rules_apply_only_to_the_accounts_api_workload(self):
        for name, policy in self.policies.items():
            if name == "default-deny-egress":
                continue
            with self.subTest(policy=name):
                self.assertEqual(policy["spec"]["podSelector"], {"matchLabels": {"app": "accounts-api"}})

    def test_no_rule_allows_the_internet_directly(self):
        for name, policy in self.policies.items():
            for rule in policy["spec"].get("egress", []):
                with self.subTest(policy=name):
                    self.assertTrue(rule.get("to"), "a rule with no 'to' allows every destination")
                    self.assertTrue(rule.get("ports"), "a rule with no 'ports' allows every port")
                    ports = {p["port"] for p in rule["ports"]}
                    for peer in rule["to"]:
                        if "ipBlock" in peer:
                            cidr = peer["ipBlock"]["cidr"]
                            self.assertIn(cidr, self.ALLOWED_CIDRS, "unexpected IP destination")
                            self.assertEqual(ports, {self.ALLOWED_CIDRS[cidr]})
                        else:
                            self.assertIn("namespaceSelector", peer)
                            self.assertIn("podSelector", peer)

    def test_the_only_external_route_is_the_proxy(self):
        rule = self.policies["accounts-api-allow-egress-proxy"]["spec"]["egress"]
        self.assertEqual(rule, [{
            "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "egress-system"}},
                    "podSelector": {"matchLabels": {"app": "egress-proxy"}}}],
            "ports": [{"protocol": "TCP", "port": 3128}],
        }])


class IngressNetworkPolicy(unittest.TestCase):
    """threat-model.md T3: other tenants must not be able to connect to accounts-api."""
    policies = {n: p for n, p in ALL_NETWORK_POLICIES.items() if p["spec"]["policyTypes"] == ["Ingress"]}

    ALB_SUBNETS = {"10.0.40.0/24", "10.0.41.0/24"}   # placeholders
    APPLICATION_PORT = 8080                          # placeholder

    def test_default_deny_covers_every_pod_and_allows_nothing(self):
        spec = self.policies["default-deny-ingress"]["spec"]
        self.assertEqual(spec["podSelector"], {})
        self.assertNotIn("ingress", spec)

    def test_there_is_exactly_one_allow_policy_and_it_selects_the_workload(self):
        allows = [n for n in self.policies if n != "default-deny-ingress"]
        self.assertEqual(allows, ["accounts-api-allow-ingress-from-alb"])
        spec = self.policies[allows[0]]["spec"]
        self.assertEqual(spec["podSelector"], {"matchLabels": {"app": "accounts-api"}})

    def test_only_the_alb_subnets_may_connect_and_only_to_the_application_port(self):
        rules = self.policies["accounts-api-allow-ingress-from-alb"]["spec"]["ingress"]
        self.assertEqual(len(rules), 1)
        self.assertEqual({peer["ipBlock"]["cidr"] for peer in rules[0]["from"]}, self.ALB_SUBNETS)
        self.assertTrue(all(set(peer) == {"ipBlock"} for peer in rules[0]["from"]))
        self.assertEqual(rules[0]["ports"], [{"protocol": "TCP", "port": self.APPLICATION_PORT}])


class ContainmentRunbook(unittest.TestCase):
    """The quarantine step works only if it removes the label the Service and allow policies select."""

    def test_containment_removes_the_app_label_and_cordons_the_node(self):
        with open(os.path.join(ROOT, "runtime", "README.md")) as f:
            runbook = f.read()
        self.assertIn("kubectl -n accounts-api label pod <pod> quarantine=true app-\n", runbook)
        self.assertIn("kubectl cordon <node>", runbook)

    def test_every_allow_policy_selects_the_label_that_containment_removes(self):
        for name, policy in ALL_NETWORK_POLICIES.items():
            if name.startswith("default-deny"):
                self.assertEqual(policy["spec"]["podSelector"], {})
            else:
                self.assertEqual(policy["spec"]["podSelector"], {"matchLabels": {"app": "accounts-api"}})


# ---------------------------------------------------------------- Egress proxy

def squid_rules():
    with open(SQUID_CONF) as f:
        return [line.split() for line in f if line.strip() and not line.startswith("#")]


class EgressProxyAllowlist(unittest.TestCase):
    def test_exactly_one_allow_rule_then_deny_all(self):
        access = [r for r in squid_rules() if r[0] == "http_access"]
        self.assertEqual(access, [["http_access", "allow", "CONNECT", "kyc_provider", "https_port"],
                                  ["http_access", "deny", "all"]])

    def test_allowlist_is_one_exact_hostname_on_443(self):
        acls = {r[1]: r[2:] for r in squid_rules() if r[0] == "acl"}
        self.assertEqual(acls["kyc_provider"], ["dstdomain", KYC_HOSTNAME])  # no leading dot: no subdomains
        self.assertEqual(acls["https_port"], ["port", "443"])
        self.assertEqual(acls["CONNECT"], ["method", "CONNECT"])

    @unittest.skipUnless(HAVE_DOCKER, "Docker is not available")
    def test_squid_accepts_the_configuration(self):
        done = run("docker", "run", "--rm", "-v", f"{SQUID_CONF}:/etc/squid/squid.conf:ro",
                   "--entrypoint", "squid", SQUID_IMAGE, "-k", "parse", "-f", "/etc/squid/squid.conf")
        output = done.stdout + done.stderr
        self.assertEqual(done.returncode, 0, output)
        self.assertNotIn("FATAL", output)
        self.assertNotIn("ERROR", output)


@unittest.skipUnless(HAVE_DOCKER and os.environ.get("EGRESS_LIVE_TEST") == "1",
                     "set EGRESS_LIVE_TEST=1 to send real requests through the proxy")
class EgressProxyLive(unittest.TestCase):
    """Runs the real configuration with example.com standing in for the KYC provider."""

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp()
        with open(SQUID_CONF) as f:
            conf = f.read().replace(KYC_HOSTNAME, "example.com")
        cls.conf = os.path.join(cls.work, "squid.conf")
        with open(cls.conf, "w") as f:
            f.write(conf)
        run("docker", "rm", "-f", "egress-test-proxy")
        run("docker", "network", "rm", "egress-test")
        run("docker", "network", "create", "egress-test")
        run("docker", "run", "-d", "--name", "egress-test-proxy", "--network", "egress-test",
            "-v", f"{cls.conf}:/etc/squid/squid.conf:ro", SQUID_IMAGE)
        time.sleep(6)

    @classmethod
    def tearDownClass(cls):
        run("docker", "rm", "-f", "egress-test-proxy")
        run("docker", "network", "rm", "egress-test")
        shutil.rmtree(cls.work, ignore_errors=True)

    def request(self, url):
        done = run("docker", "run", "--rm", "--network", "egress-test", CURL_IMAGE, "-sS", "-o", "/dev/null",
                   "-m", "20", "-w", "%{http_code} %{http_connect}", "-x", "http://egress-test-proxy:3128", url)
        return done.stdout.strip()

    def test_the_allowed_hostname_on_443_is_tunnelled(self):
        self.assertEqual(self.request("https://example.com/"), "200 200")

    def test_everything_else_is_denied(self):
        for url, expected in (
            ("https://www.wikipedia.org/", "000 403"),   # another hostname
            ("https://sub.example.com/", "000 403"),     # a subdomain of the allowed hostname
            ("https://example.com:8443/", "000 403"),    # the allowed hostname on another port
            ("http://example.com/", "403 000"),          # plain HTTP to the allowed hostname
        ):
            with self.subTest(url=url):
                self.assertEqual(self.request(url), expected)


if __name__ == "__main__":
    unittest.main()
