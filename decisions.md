# Decisions

## Assumptions and security decisions

### Assumptions

Made while writing the threat model (Section 1):

- **System context:** taken from the summary bullets only (EKS in ap-south-1, RDS, stream, KYC, CloudFront + ALB, shared cluster, GitHub Actions, multi-account org, team sizes). Anything not in that list is assumed below.
- **Message stream:** an AWS-managed service (MSK or Kinesis) in the same account, reached privately, and consume-only for accounts-api. It is therefore covered by T2 (workload IAM) rather than ranked as its own threat.
- **Workload identity:** accounts-api can be given its own IAM role (IRSA or EKS Pod Identity) rather than inheriting the node role.
- **CI authentication:** we control the GitHub Actions workflows and can use GitHub OIDC federation to AWS instead of stored access keys.
- **Cluster ownership:** the platform team owns the shared cluster; we own the accounts-api namespace and may propose cluster-wide admission policy, but cannot dictate other teams' workload configuration.
- **KYC integration:** outbound-only calls from accounts-api to a stable set of provider hostnames; no inbound webhooks from the provider.
- **Engineer access:** engineers reach AWS and the cluster through SSO with short-lived sessions, not long-lived IAM users.
- **Multi-account org:** a separate log-archive (or security) account exists or can be created to hold audit logs away from the workload account.
- **Edge:** CloudFront and ALB are already in place with Shield Standard; the ALB is not directly reachable except through CloudFront.
- **Later sections:** the controls named against T1–T5 are what I expect Sections 2–6 to cover; if a section's brief differs, the threat model's control lines will be updated to match.

Made for Section 2 (build and release integrity):

- **Repository:** `mal/accounts-api`, default branch `main`, with the application source and a `Dockerfile` at the repository root. This submission does not contain the application.
- **AWS account model:** `123456789012` is a placeholder for a tooling/build account. ECR and the `accounts-api-github-build` role live there. Production EKS and RDS live in a separate workload/production account.
- **OIDC provider:** the GitHub OIDC provider (`token.actions.githubusercontent.com`) already exists in the tooling account, so it is referenced, not created.
- **Branch protection:** Branch protection and required review are assumed GitHub repository controls and are not implemented as part of this assessment.
- **Registry:** ECR supports OCI 1.1 referrers for signatures and attestations, so these should coexist with immutable application tags. This interaction has not been exercised against a live ECR repository in this assessment.

Made for Section 3 (pipeline gates and the waiver path):

- **GitHub controls:** production enforces branch protection on `main` with required code-owner review, required signed commits, and `security-gates` as a required status check. These are repository settings and are not implemented in this assessment.
- **Code owners:** a GitHub team `@mal/platform-team` exists and holds the two platform engineers. With two people, each is the other's approver.
- **Application language:** unknown, so Semgrep runs its general `p/default` ruleset. A real repository would narrow this to its languages.
- **Incident tracker:** incidents and tickets have keys of the form `INC-123` or a URL.
- **Emergency override:** branch protection allows only named platform maintainers to bypass it, and GitHub records each use in the audit log. This is a repository setting and is not implemented in this assessment.

Made for Section 4 (review and remediate):

- **Supplied artefacts:** I worked from the brief's description of each artefact, not the original files. The bad fixtures are reconstructions that contain exactly the listed defects and nothing else.
- **Container runtime:** assuming standard modern EKS nodes using containerd, the `docker.sock` mount is most likely inert. If any node group still runs Docker, that defect becomes the most exploitable one.
- **Application behaviour:** accounts-api does not call the Kubernetes API, can run as a non-root user with a read-only root filesystem and a writable `/tmp`, logs to stdout, and takes its secrets from Secrets Manager using its pod identity (delivered as mounted files; see Section 6).
- **Pod identity with no API token:** the AWS identity token is projected separately, so `automountServiceAccountToken: false` does not break it.
- **Security groups for pods** are enabled on the cluster, so the database can admit accounts-api pods without admitting every tenant on the shared nodes.
- **Workload account:** `111122223333` is a placeholder for the workload/production account. The KMS key ID, secret names and stream name are placeholders.
- **Message stream:** Kinesis Data Streams with IAM authentication. If it is MSK or does not use IAM, the stream statement in the pod policy changes or is deleted.
- **CloudTrail:** the supplied trail is a per-account trail writing to a bucket and key owned by the log-archive account. An organisation trail would be the stronger design.
- **Kyverno** is, or can be, installed on the shared cluster by the platform team.
- **Cross-account image pull:** The production/workload account is assumed to have read-only cross-account pull access to the signed accounts-api ECR repository in the tooling account. The ECR repository policy is outside the supplied Section 4 artefacts.

Made for Section 5 (admission and runtime):

- **Platform-run components:** Kyverno, Falco with Falcosidekick, and the egress proxy are installed and operated by the platform team in their own namespaces. This repository supplies the policies, the rule and the allowlist, not those deployments.
- **Alert path:** Falco to Falcosidekick to the central alerting/SIEM, and PagerDuty to the on-call platform engineer for CRITICAL alerts.
- **NetworkPolicy is enforced** on the cluster (VPC CNI network policy agent, Calico or Cilium).
- **KYC provider:** one API hostname on port 443, without published stable IP ranges. `api.kyc-provider.example` is a placeholder.
- **Private dependencies:** RDS, AWS APIs through VPC interface endpoints, and the EKS Pod Identity Agent. The CIDRs in the NetworkPolicy are placeholders.
- **Ingress path:** the ALB is managed by the AWS Load Balancer Controller with IP targets, so it reaches pods directly from the ALB subnets. The ALB subnet CIDRs (`10.0.40.0/24`, `10.0.41.0/24`) and the application port (`8080`) are placeholders.
- **Application behaviour:** it starts no child processes, and its HTTP client honours `HTTPS_PROXY` and `NO_PROXY`.

Made for Section 6 (secrets and data protection):

- **Platform-run component:** the Secrets Store CSI Driver and its AWS provider are installed by the platform team, at a version that supports EKS Pod Identity. Auto-rotation is not a driver default; it must be enabled with a poll interval of about two minutes, as specified in `kubernetes/secrets-store-csi-driver/values.yaml`.
- **Application behaviour:** accounts-api reads its credentials from files and re-reads the database credential when it opens a connection or sees an authentication failure.
- **Database TLS:** The accounts-api database client is required to use TLS. Production should also enable the RDS PostgreSQL `rds.force_ssl` parameter so non-TLS clients are rejected.
- **Rotation function:** The Terraform configures the secret and rotation schedule; the production rotation Lambda implementing the alternating-user strategy is specified but not deployed/tested in this assessment. Its ARN and role are Terraform variables.
- **KYC provider:** whether keys can overlap and be rotated self-service is unknown and is an external dependency.
- **Logging:** the application's code and the central log pipeline are outside this repository, so the log redaction document is a specification for both.

### Security decisions

#### Section 6: Secrets and data protection (T2, T4, T5)

- **Secrets Manager is the source of truth, delivered by the Secrets Store CSI Driver.** The pod mounts its two secrets read-only from an in-memory volume, fetched with its own pod identity. Nothing is synced into a Kubernetes Secret, so the value is not in etcd, and nothing is in an environment variable.
- **This replaces the Section 4 mechanism, not the model.** Section 4 had the application call Secrets Manager itself. The source of truth, the pod identity and the two named secrets are unchanged; only the delivery step moved to the CSI driver. The pod policy gained one action, `secretsmanager:DescribeSecret`, on the same two secrets, because the AWS provider needs it.
- **Both secrets use the same path.** The brief asks for the database credential; the KYC key is delivered identically so that no second mechanism exists.
- **One JSON file for the database credential.** Alternating-users rotation changes username and password together, so they must be read together.
- **Rotation reaches the process in three steps:** Secrets Manager rotation, then the CSI reconciler updates the mounted file, then the application re-reads the file or the pods are rolled. The reconciler must be enabled (it is off by default), and the driver never reloads the application, which is why the emergency procedure rolls the pods instead of waiting.
- **Alternating users for the database (specified, not implemented here).** The previous user stays valid until the next rotation, so scheduled rotation needs no restart and causes no outage. In an emergency that same property means the old user must be killed explicitly, which is step 4 of the procedure.
- **Emergency targets are step budgets, not measurements:** 15 minutes for the database credential, 30 minutes for the KYC key where the provider allows self-service rotation.
- **No AWS key to rotate.** accounts-api uses short-lived Pod Identity credentials. For an active compromise the control is revoking the role's sessions, not rotation.
- **No secret value in Terraform.** `terraform/secrets.tf` defines the secrets, their key and the 30-day schedule, with no secret version, so nothing sensitive reaches Git or state.
- **Key administration separated from use.** The secrets key policy lets the administrator role manage the key but not decrypt, and lets the workload decrypt only through Secrets Manager.
- **Log redaction by allowlist.** The application emits only named fields and no free-text messages; the pipeline stage is a backstop whose hits are treated as application bugs. Pattern matching is not presented as making logs safe, and the specification lists what still leaks.
- **Encryption statement:** Customer data in RDS and secrets in Secrets Manager are encrypted at rest with customer-managed AWS KMS keys, with key administration separated from workload use; TLS protects data in transit. This reduces exposure from stolen storage/snapshots and unauthorised direct access to encrypted backing data, but does not protect data from an authorised or compromised running accounts-api process.
- **Not verified live:** the SecretProviderClass was not applied to a cluster, no rotation was run, and the emergency procedures have not been drilled.


#### Section 5: Admission and runtime (T2, T3, T4, T5)

- **Reuse, not duplicate.** The six Section 4 policies are the admission baseline. Section 5 adds only a mode to each and two audit copies of the host-escape checks.
- **Enforce where we own it, audit where we do not.** All six policies deny in the `accounts-api` namespace from day one: the corrected workload already complies, so nothing can break. Host namespaces and hostPath are also checked in every other tenant namespace, but in audit, because about a dozen teams share the cluster and a day-one deny would block their deploys without warning. The four accounts-api-specific policies are not extended to other teams at all.
- **This narrows two Section 4 policies.** `disallow-host-namespaces` and `disallow-host-path` denied cluster-wide in Section 4. They now deny in `accounts-api` only, with audit copies for the rest. A test keeps each pair's validation identical.
- **Promotion is criteria-based:** two weeks in audit, zero unexplained violations, an owner for each remaining one, no false positives in the last week, and a week's notice to affected teams. Details in `policies/kubernetes/README.md`.
- **Trade-off accepted:** until promotion, another tenant can still run a host-access pod, so the T3 path stays open and is covered only by detection.
- **One runtime rule, on purpose.** A 2-person team can respond to a rule that should never fire. The rule is scoped to one container and keyed to what this workload never does (start a shell or tool, or execute from `/tmp`), so it can page without becoming noise. It does not require a terminal, unlike Falco's default shell rule.
- **Containment by label.** `kubectl label pod <pod> quarantine=true app-` removes the `app` label, which takes the pod out of the Service and out of every allow NetworkPolicy. Only the namespace's default-deny ingress and egress policies still apply, so its network is cut in both directions while it keeps running as evidence. The pod is not deleted during initial containment.
- **Egress in two layers.** NetworkPolicy cannot match a hostname, and the KYC provider has no stable IP ranges, so NetworkPolicy allows only the proxy and the proxy allows only the hostname. Hard-coding CDN ranges was rejected as both fragile and too broad.
- **Proxy as specification.** The allowlist and the proxy's NetworkPolicy are provided and tested; the proxy Deployment is the platform team's. The allowlist was run live in a container and behaves as designed.
- **Stated limits.** The egress control does not inspect content, so data can still leave inside requests to the KYC hostname; it depends on the proxy's configuration and DNS; and DNS itself remains an exfiltration channel. These are listed in `kubernetes/egress-proxy/README.md`.
- **Ingress is default-deny too (T3).** Every pod in the namespace denies ingress, and accounts-api accepts connections only from the ALB subnets on its application port. No other tenant, and no other pod in the namespace, can connect. This is the NetworkPolicy that T3's control line promises.
- **Not verified live:** nothing in this section was applied to a live cluster, and the Falco rule was validated but not fired.


#### Section 4: Review and remediate (T2, T3, T5)

- **Ranking is by exploitability here, not scanner severity.** The ranked tables are in `review/`. Two examples where they differ: the over-broad Role ranks above the `docker.sock` mount because it needs no escape and works on any runtime, and PostgreSQL open to the internet ranks first although Trivy's built-in checks do not flag it at all.
- **Kyverno for Kubernetes admission**, written as `ValidatingPolicy` (CEL). The older `ClusterPolicy` format is reported as deprecated by the current Kyverno CLI, so it was not used.
- **Policy scope follows ownership.** The policies deny in the `accounts-api` namespace; this team cannot dictate other teams' workloads. Host namespaces and hostPath matter cluster-wide because one tenant's host access endangers all tenants (T3); Section 5 sets how those two are rolled out to other namespaces.
- **No Role at all.** The least-privilege fix for the supplied Role is to delete it and stop mounting the token, because the workload does not use the Kubernetes API. `tests/fixtures/kubernetes/good-role.yaml` shows what an acceptable Role looks like, so the RBAC policy is tested as more than a blanket deny.
- **Trivy stays the single IaC scanner.** Built-in checks cover three of the eight Terraform defects at blocking severity. Five custom Rego checks in `policies/terraform/` cover the rest, and one in `policies/iam/` covers the IAM policy. They run inside the existing Trivy step, so findings use the same gate and waiver path as everything else.
- **Custom check severity is about blocking.** All custom checks are HIGH or CRITICAL so the gate blocks on them. Their severity is not the exploitability ranking.
- **Each control is tested on its own.** Beyond bad-fails and good-passes, the tests break one control at a time in the corrected artefact and require the right policy to catch it. This stops a policy that never fires from looking healthy.
- **Good fixtures cannot drift.** A test requires each good fixture to be byte-identical to the real artefact.
- **Only supplied defects were fixed,** with three additions, each explained in `review/`: resource requests and a memory limit (shared cluster), no mounted API token (part of the RBAC fix), and a KMS key on CloudTrail (Trivy flags its absence as HIGH and the fix is one line).
- **Not enforced:** the Kyverno policies are tested with the Kyverno CLI, not on a live cluster. Deliberately insecure fixtures under `tests/fixtures/` are skipped by the repository-wide Semgrep and Trivy scans; code-owner review on `/tests/` is the control against hiding real configuration there.

#### Section 3: Pipeline gates and the waiver path (T1, T2, T4)

**Tools.** Three tools cover four gates.

| Tool | Gate | Why this one | Trade-off |
|---|---|---|---|
| Trivy | SCA and IaC | One tool, one vulnerability database and one report format for dependencies, image packages and Terraform/Kubernetes | A single vendor's database and rule quality; a Trivy outage or bad release takes out two gates at once |
| Semgrep | SAST | Fast, needs no build, and rules are readable enough for a 2-person team to tune | The community engine has no cross-file taint analysis, so deeper flows are missed |
| Gitleaks | Secrets | Scans full git history natively, runs offline, no licence or service | Pattern-based; it cannot check whether a secret is live, so every match is treated as credible |

Consolidation is deliberate: fewer tools means fewer report formats, fewer pins to maintain and one place to tune. The cost is less overlap between scanners, so a miss by one tool is not caught by another.

**Thresholds.**

| Gate | Blocks | Why |
|---|---|---|
| Secrets | Any detection | A leaked credential is exploitable immediately and cannot be un-leaked; history is scanned because deleting a file does not remove the secret |
| SAST | Severity ERROR/HIGH/CRITICAL and confidence HIGH | Only findings that are both serious and precise are worth stopping a merge for; the rest are reported |
| SCA | HIGH and CRITICAL | The severities most likely to be exploitable through an internet-facing API (T2) |
| IaC | HIGH and CRITICAL | Misconfigurations at this level are usually direct exposure: public access, missing encryption, wildcard IAM |

MEDIUM and below never block. These are starting thresholds and would be tuned on the observed false-positive rate.

**Design.**

- **One decision point.** Scanners only write reports; `scripts/waivers.py` applies thresholds and waivers. It is unit-tested, and the tests run in the pipeline before the gate.
- **Fail closed.** A scanner that fails, or a report that is missing or unreadable, blocks. Gitleaks exits 0 with an empty report when it cannot read the git log, so the workflow also requires at least one scanned commit and no error lines.
- **Full-history secret scan.** `fetch-depth: 0`, an explicit check that the clone is not shallow, and `gitleaks git --log-opts="--all"`.
- **Scanners pinned by image digest**, run without credentials. The workflow has `contents: read` only and no OIDC token, so a malicious pull request has nothing to steal (T1).
- **Daily run.** New CVEs and expired waivers surface on `main` without waiting for a commit.
- **Waivers are exact and short-lived.** One rule, one file, one resource, at most 30 days, two different people. No wildcards. Details in `waivers/README.md`.
- **Approval and signing.** Approval is the code-owner review. CI also checks that the last commit to `waivers.yaml` is GitHub-verified whenever an entry exists. A detached signature was not added because its trusted-key list would sit in the same repository under the same review rule.
- **Secrets in history.** Revoking a credential does not clear a full-history finding. A temporary secret waiver requires immediate revocation, an exposure investigation, and, before it expires, either removal from repository history or migration to an explicitly approved exact-fingerprint baseline (`.gitleaksignore`) for the revoked secret; the temporary waiver is then removed. Repeated renewal is not the intended remediation. Details in `waivers/README.md`.
- **Break-glass** reuses the waiver file: incident ID, two people, at most 24 hours, never bypasses the secret gate, and turns CI red when it expires. If the required check still cannot go green, a named maintainer may use the audited branch-protection override. Details in `break-glass.md`.
- **Tuned, not waived: ECR scan-on-push (Trivy AWS-0030, HIGH).** The IaC gate flags the Section 2 ECR repository for not using native ECR scanning. The architecture was not changed to make the scanner green. Trivy is the consolidated vulnerability scanner and already scans the image before merge; native ECR scanning would be a second, overlapping scanner producing findings that gate nothing and that a 2-person team would not triage. The check is switched off for that one resource with an inline `#trivy:ignore:AWS-0030` and the rationale beside it in `terraform/ecr.tf`. Residual gap: an image already in ECR is not rescanned when a new CVE is published; the daily gate run rebuilds and scans `main`, which covers the current release but not older tags.
- **Waiver versus tuning.** A waiver is for a real finding accepted for a short time. Tuning is for a rule that does not apply to the chosen architecture; it is permanent, scoped to one resource, written next to the code with its reason, and reviewed by code owners.

**Known limits.**

- A pull request can edit `security-gates.yml` itself. Code-owner review on `/.github/` is the control; an organisation-level required workflow would be stronger.
- Semgrep rules are fetched from the Semgrep registry at run time and are not pinned.
- A Semgrep waiver covers one rule in one file, not one line, because line numbers move.
- The scanners honour their own inline ignore comments (`#trivy:ignore`, `nosemgrep`, `gitleaks:allow`). One is used deliberately for AWS-0030; any other would bypass the waiver file. The control is code review, with code-owner review on `/terraform/`, `/.github/` and `.gitleaksignore`; application source is not code-owned here.
- The signed-commit check uses the GitHub API and has not been exercised in a live repository.

#### False positives

- **Expected load (estimate, not measured).** Secrets: a burst on the first full-history scan of an existing repository, then rare. SAST at high confidence: low. IaC: a burst at adoption, then low. SCA is the steady source of work: new CVEs arrive in unchanged code, and most are real but not reachable.
- **What to tune first.** (1) Stop blocking on vulnerabilities with no fix available (`--ignore-unfixed`), since a block nobody can act on only produces waivers. (2) Add a reviewed Gitleaks allowlist for test fixtures. (3) Trim the Semgrep ruleset to rules that have proved precise on this codebase.
- **How to decide.** Track waivers raised per month and the share that were false positives. A rule that mostly generates waivers is demoted to report-only.
- **Why noise matters.** With about 40 engineers and 2 platform engineers, every false block costs scarce review time. Engineers who learn that red usually means noise start waiving by reflex and push to have the gate removed, and then the real finding is missed too.
- **Waivers are not ignores.** They are temporary, named, approved and visible on every run, and they fail the build when they expire. A waiver cannot be made permanent. The only permanent exceptions are rule tuning and the secret baseline described above, each exact, reasoned and separately reviewed.

#### Section 2: Build and release integrity (T1, supply-chain part of T2)

- **OIDC, no static keys.** The workflow assumes `accounts-api-github-build` with a short-lived token. The trust policy matches one exact `sub`, `repo:mal/accounts-api:ref:refs/heads/main`, using `StringEquals`. Branch scope was chosen over environment scope because it needs no GitHub-side configuration to be safe. `iam/README.md` lists what it denies.
- **Build and deploy are separate accounts and separate roles.** The build role exists only in the tooling account. Its policy allows `ecr:GetAuthorizationToken` plus push and read actions on the `accounts-api` repository, which is what building, signing, attesting and verifying need. It has no EKS, RDS, Secrets Manager or IAM permissions and no `sts:AssumeRole`, so a stolen build token cannot deploy or reach the production account. The worst it can do is push another image, which is what signature verification is for.
- **Deployment is out of scope for Section 2.** Production deployment would use a separately scoped deployment role in the production account, with its own trust policy. Cross-account image pull from the tooling ECR repository belongs with that work and is not implemented here.
- **Actions pinned to commit SHAs**, with the version in a comment. ECR login uses the AWS CLI to avoid one more third-party action. Workflow token permissions default to none.
- **Keyless signing.** Trust root: Sigstore's public Fulcio CA and Rekor log (via the TUF root shipped with Cosign), which bind each signature to the GitHub OIDC identity of `build.yml` on `main`. There is no signing key to store, rotate or leak, which suits a 2-person platform team.
- **Cost of keyless:** the repository name, workflow path, commit SHA and image digest are written to the public Rekor log. Accepted. If that metadata is considered sensitive, the alternative is a KMS key, at the price of managing key access.
- **SBOM as attestation.** Syft scans the pushed image by digest and `cosign attest` stores the SPDX document as a signed in-toto statement in ECR beside the image. It is not uploaded as a workflow artifact, because artifacts expire and are not bound to the image.
- **One commit, one image.** Tags are the full commit SHA and the ECR repository is `IMMUTABLE`. Everything after the push uses the digest.
- **Reruns fail by design.** A second run for the same commit SHA will encounter the immutable tag and stop at the push. This is a deliberate consequence of immutable release identifiers: a released tag must never point at a different image. ECR immutability is not weakened to make reruns convenient; if a run fails after the push, release from a new commit.
- **BuildKit provenance and SBOM are disabled** because they are unsigned and turn the image into an index. The signed Cosign attestation is the single source.
- **No vulnerability scanner in this section.** The SBOM records what is in the image; it does not gate on it.

#### What the signature proves, and what it does not

It proves that this exact image digest was signed by the `build.yml` workflow of `mal/accounts-api` running on `main`, and that the signing event is in a public transparency log.

It does not prove that:

- the source code is free of vulnerabilities;
- the dependencies or base image are safe (a compromised dependency is signed just as faithfully);
- the application is logically secure;
- the change was reviewed (that depends on branch protection, not on the signature);
- the running workload uses the signed image. Until an admission controller verifies signatures, an unsigned image can still be deployed.
