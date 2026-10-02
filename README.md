# Senior DevSecOps Take-Home Assessment

This repository contains my submission for a Senior DevSecOps take-home assessment for `accounts-api`, a service holding customer banking data on a shared EKS cluster. It covers a threat model, build and release integrity, pipeline gates, remediation of supplied artefacts with policy-as-code, admission and runtime controls, and secrets and data protection.

Start with `threat-model.md` (five ranked threats, T1 to T5; every control cites one) and `decisions.md` (assumptions and reasoning, by section).

Nothing here has been applied to a real AWS account or a live cluster. Account IDs, hostnames, CIDRs and the image digest are placeholders.

**Workflow status in this repository.** `build.yml` is expected to fail when it runs here: it needs the tooling AWS account, an application `Dockerfile`, and a repository named `mal/accounts-api`, none of which exist for this submission. `security-gates.yml` needs no credentials and is the workflow that should run. The tests below do not depend on either workflow.

## How to run policy tests

### What you need

- Docker, running.
- Python 3.12.
- Internet access on the first run, to pull the scanner images.

Nothing else needs installing. Kyverno, Trivy, Falco and Squid run as the same digest-pinned container images the pipeline uses.

### Run everything

From the repository root:

```sh
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -r scripts/requirements.txt
python3 -m unittest discover -s tests -v
```

Expected last lines:

```
Ran 96 tests in ...s

OK (skipped=2)
```

The two skipped tests send real requests through the egress proxy and are opt-in (see below). The first run downloads the images and takes a few minutes; after that the suite takes about half a minute.

If Docker is not running, the tests that need it are skipped, not failed, so check the skip count. To make a missing Docker daemon an error, as the pipeline does, set `REQUIRE_POLICY_TESTS=1`.

### What the tests prove

| Test file | Tests | Proves |
|---|---|---|
| `tests/test_policies.py` | 22 | The supplied (bad) workload manifest, Terraform and IAM policy are rejected, with every supplied defect detected. The corrected versions pass. Breaking any single control in a corrected artefact is caught. Each admission policy's audit or enforce mode matches the documented classification. |
| `tests/test_runtime_and_egress.py` | 19 | Falco accepts the runtime rule and it is scoped to the accounts-api container. No NetworkPolicy rule allows the internet directly; ingress is default-deny with one allowed source. The egress proxy allowlist is one hostname on port 443 followed by deny-all, and Squid accepts it. |
| `tests/test_secrets_and_logging.py` | 23 | Secrets are mounted read-only from Secrets Manager with the pod identity; no Kubernetes Secret, environment variable or Terraform value holds a credential. Rotation intervals and targets are stated. Every log redaction pattern matches its examples and does not mask safe operational values. |
| `tests/test_waivers.py` | 32 | Waivers must be exact, approved by a second person and unexpired. Break-glass bypasses findings but never secrets or a scanner that failed to run. |

For each reviewed artefact the policy tests check three things:

- the bad fixture fails;
- the good fixture passes, and is byte-identical to the real artefact in the repository;
- changing one control at a time in the good fixture is caught by the expected policy.

### Run one area

```sh
python3 -m unittest discover -s tests -p 'test_policies.py' -v             # Sections 4 and 5: admission, Terraform, IAM
python3 -m unittest discover -s tests -p 'test_runtime_and_egress.py' -v   # Section 5: runtime rule, network policies, egress proxy
python3 -m unittest discover -s tests -p 'test_secrets_and_logging.py' -v  # Section 6: secrets delivery, rotation, log policy
python3 -m unittest discover -s tests -p 'test_waivers.py' -v              # Section 3: waivers and break-glass (no Docker needed)
```

To also start the egress proxy and send real requests through it, with `example.com` standing in for the KYC provider:

```sh
EGRESS_LIVE_TEST=1 python3 -m unittest discover -s tests -p 'test_runtime_and_egress.py' -v
```

### Run a policy engine by hand

The same checks without the test harness, to see the engines' own output.

```sh
KYVERNO=ghcr.io/kyverno/kyverno-cli@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a
TRIVY=ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa

# Kubernetes admission: the bad manifest fails all six enforced policies (exit 1), the good one passes (exit 0)
docker run --rm -v "$PWD:/repo" -w /repo $KYVERNO apply policies/kubernetes --resource tests/fixtures/kubernetes/bad.yaml
docker run --rm -v "$PWD:/repo" -w /repo $KYVERNO apply policies/kubernetes --resource tests/fixtures/kubernetes/good.yaml

# Terraform and IAM: the bad fixtures report findings (exit 1), the good ones report none (exit 0)
for target in tests/fixtures/terraform/bad tests/fixtures/terraform/good tests/fixtures/iam/bad.json tests/fixtures/iam/good.json; do
  docker run --rm -v "$PWD:/repo" -w /repo $TRIVY config --severity HIGH,CRITICAL --exit-code 1 \
    --raw-config-scanners terraform \
    --misconfig-scanners azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,json \
    --config-check policies/terraform --config-check policies/iam --check-namespaces user "$target"
done
```

| Fixture | Expected result |
|---|---|
| `tests/fixtures/kubernetes/bad.yaml` | `pass: 0, fail: 6`, exit 1 |
| `tests/fixtures/kubernetes/good.yaml` | `fail: 0`, exit 0 |
| `tests/fixtures/terraform/bad` | 9 findings covering all 8 supplied defects, exit 1 |
| `tests/fixtures/terraform/good` | no findings, exit 0 |
| `tests/fixtures/iam/bad.json` | `ACCT-IAM-001`, exit 1 |
| `tests/fixtures/iam/good.json` | no findings, exit 0 |

### Other checks

```sh
python3 scripts/waivers.py validate                                    # schema, scope and expiry of waivers/waivers.yaml
jq -e . iam/github-oidc-trust-policy.json                              # trust policy is valid JSON
terraform -chdir=terraform init -backend=false && terraform -chdir=terraform validate
```

## Repository structure

| Path | Contents |
|---|---|
| `threat-model.md` | Section 1: trust boundaries and the five ranked threats |
| `decisions.md` | Assumptions and security decisions for every section |
| `.github/workflows/` | `build.yml` (Section 2) and `security-gates.yml` (Section 3) |
| `.github/CODEOWNERS` | Paths that need platform-team review |
| `iam/` | GitHub OIDC trust policy and the accounts-api pod policy |
| `terraform/` | ECR and build role, corrected RDS and CloudTrail, secrets and rotation schedule |
| `kubernetes/` | Corrected workload, network policies, secrets delivery, egress proxy specification |
| `policies/kubernetes/` | Kyverno admission policies, with modes and promotion criteria in its `README.md` |
| `policies/terraform/`, `policies/iam/` | Custom Trivy checks |
| `review/` | Section 4 ranked defect notes for the three supplied artefacts |
| `runtime/` | Falco rule, alert routing and responder runbook |
| `data-protection/` | Secrets delivery path, rotation, log redaction specification |
| `waivers/`, `break-glass.md` | Waiver file and process, emergency path |
| `scripts/waivers.py` | Waiver validation and the merge gate decision |
| `tests/` | Test suites, and the bad and good fixtures under `tests/fixtures/` |

## Section summaries

### Build and release integrity (Section 2)

`.github/workflows/build.yml` runs on every push to `main`. It builds the image, pushes it to ECR tagged with the commit SHA, generates an SBOM with Syft, attaches the SBOM to the image as a signed attestation, signs the image digest with Cosign (keyless), and verifies both before finishing. Rationale and limits are in `decisions.md`; the AWS trust scope is in `iam/README.md`.

Account model: `123456789012` is a placeholder for a tooling/build account, which holds ECR and the GitHub OIDC build role. Production EKS and RDS are in a separate workload account. The build role can only push to and read from the `accounts-api` ECR repository; it cannot deploy. Deployment would use a separately scoped role and is not part of this section.

**Verify a built image.** Requires `cosign` v3, `jq`, and read access to the ECR repository.

```sh
REPO=123456789012.dkr.ecr.ap-south-1.amazonaws.com/accounts-api
IDENTITY=https://github.com/mal/accounts-api/.github/workflows/build.yml@refs/heads/main
ISSUER=https://token.actions.githubusercontent.com

aws ecr get-login-password --region ap-south-1 \
  | docker login --username AWS --password-stdin "${REPO%%/*}"

# Resolve the commit-SHA tag to a digest, then use only the digest.
DIGEST=$(aws ecr describe-images --region ap-south-1 --repository-name accounts-api \
  --image-ids imageTag=<git-commit-sha> --query 'imageDetails[0].imageDigest' --output text)

# 1. Signature: was this digest signed by build.yml on main?
cosign verify "$REPO@$DIGEST" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

# 2. SBOM attestation: same identity check, then list the packages in the SBOM.
cosign verify-attestation "$REPO@$DIGEST" --type spdxjson \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq -r '.predicate.packages[].name' | sort -u
```

Both commands exit non-zero if the signature is missing or was made by any other repository, branch or workflow file.

**Check tag immutability.**

```sh
aws ecr describe-repositories --region ap-south-1 --repository-names accounts-api \
  --query 'repositories[0].imageTagMutability'   # expect "IMMUTABLE"

# Re-pushing a different image under an existing tag must be rejected by ECR.
docker tag alpine:3 "$REPO:<git-commit-sha>" && docker push "$REPO:<git-commit-sha>"
```

A second workflow run for the same commit SHA will encounter the immutable tag and fail at the push. This is a deliberate consequence of immutable release identifiers, not a fault; release from a new commit instead.

### Pipeline gates and the waiver path (Section 3)

`.github/workflows/security-gates.yml` runs on every pull request, on every push to `main`, and daily. It holds no cloud credentials.

| Gate | Tool | Blocks a merge when |
|---|---|---|
| Secrets | Gitleaks, across the full git history | any secret is detected |
| SAST | Semgrep | a high-confidence finding of severity ERROR/HIGH or above |
| SCA | Trivy (repository dependencies, and the image when a `Dockerfile` exists) | a HIGH or CRITICAL vulnerability, unless waived |
| IaC | Trivy | a HIGH or CRITICAL misconfiguration, unless waived |

The scanners only write JSON reports. `scripts/waivers.py` makes the single pass/fail decision, and a scanner that did not run counts as a block.

- Exceptions: `waivers/README.md` (temporary, approved, expire in at most 30 days).
- Emergencies: `break-glass.md`.
- Rationale, thresholds and false-positive handling: `decisions.md`.

**Run the gates locally.** Requires Docker. Each scanner is one `docker run` line in the workflow; run the same lines from the repository root with `RUN` set as below, then apply the gate.

```sh
mkdir -p reports
RUN="docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -e TRIVY_CACHE_DIR=/tmp/trivy -v $PWD:/repo -w /repo"
# ...the Gitleaks, Semgrep and Trivy commands from security-gates.yml...
python3 scripts/waivers.py gate --reports reports
```

### Review and remediate (Section 4)

Three supplied artefacts were reviewed, fixed, and locked in with policy-as-code. Ranked defect notes are in `review/`.

| Artefact | Fixed version | Ranked notes | Policy that prevents recurrence | Bad and good fixtures |
|---|---|---|---|---|
| Workload manifest | `kubernetes/accounts-api.yaml` | `review/workload-manifest.md` | `policies/kubernetes/` (Kyverno) | `tests/fixtures/kubernetes/` |
| Terraform | `terraform/review-remediate.tf` | `review/terraform.md` | Trivy built-in checks plus `policies/terraform/` | `tests/fixtures/terraform/` |
| Pod identity IAM policy | `iam/accounts-api-pod-policy.json` | `review/iam-policy.md` | `policies/iam/` (Trivy custom check) | `tests/fixtures/iam/` |

### Admission and runtime (Section 5)

| Control | Where | Summary |
|---|---|---|
| Admission | `policies/kubernetes/` and its `README.md` | Six policies enforced in the `accounts-api` namespace from day one; two host-escape policies audit every other tenant namespace, with written promotion criteria. |
| Runtime detection | `runtime/` | One Falco rule: a shell, tool or binary from `/tmp` started in the accounts-api container. Pages the on-call platform engineer. Runbook in `runtime/README.md`. |
| Egress | `kubernetes/accounts-api-network-policy.yaml`, `kubernetes/egress-proxy/` | Default-deny egress; the only internet route is a proxy that allows one hostname on 443. Limits in `kubernetes/egress-proxy/README.md`. |
| Ingress | `kubernetes/accounts-api-network-policy.yaml` | Default-deny ingress; accounts-api accepts connections only from the ALB subnets (placeholders). |

### Secrets and data protection (Section 6)

| Topic | Where | Summary |
|---|---|---|
| Secrets delivery | `kubernetes/accounts-api-secrets.yaml`, `kubernetes/secrets-store-csi-driver/values.yaml`, `data-protection/README.md` | Secrets Manager, fetched with the pod's identity by the Secrets Store CSI Driver, mounted read-only in memory at `/mnt/secrets`. No Kubernetes Secret, no environment variable, no value in Git. |
| Rotation | `data-protection/rotation.md`, `terraform/secrets.tf` | Database credential on a 30-day schedule (emergency target 15 minutes); KYC key every 90 days (emergency target 30 minutes); no long-lived AWS credential exists. The Terraform configures the schedule; the rotation Lambda is specified, not deployed or tested here. |
| Log redaction | `data-protection/log-redaction.md`, `data-protection/log-policy.yaml` | Allowlist at the application, defensive filtering in the pipeline, an honest list of what still leaks, and the encryption statement. |
