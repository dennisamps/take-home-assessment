# Waivers

A waiver is a temporary, approved, audited exception that stops one named finding from blocking a merge. It is not an ignore list: every waiver expires, and a waiver cannot be made permanent.

`waivers.yaml` is the only place a finding can be excepted. `scripts/waivers.py` validates the file and is the single step in `security-gates.yml` that decides whether a merge is blocked.

## Fields

| Field | Meaning |
|---|---|
| `id` | Unique, `W-YYYY-NNN` |
| `scanner` | `gitleaks`, `semgrep`, `trivy-vuln` or `trivy-config` |
| `rule` | The CVE, misconfiguration ID, Semgrep rule or Gitleaks rule being waived |
| `path` | The one file the finding is reported in |
| `resource` | Package name (`trivy-vuln`), Terraform or Kubernetes resource (`trivy-config`), full commit SHA (`gitleaks`). Not used for `semgrep` |
| `reason` | Why the exception is acceptable for now |
| `reference` | Ticket key or URL that tracks the fix |
| `requested_by` / `approved_by` | GitHub handles; must be two different people |
| `created_at` / `expires_at` | Dates; at most 30 days apart |

The gate prints every blocking finding as `scanner=… rule=… path=… resource=…`. Copy those four values into the waiver exactly.

## Lifecycle

1. **Blocked.** The gate fails and prints the finding.
2. **Request.** The engineer opens a pull request that adds one entry to `waivers.yaml`, with a ticket for the real fix.
3. **Approve.** A platform-team member (CODEOWNER for `/waivers/`) reviews and approves. They are the `approved_by`.
4. **Active.** The gate reports the finding as `WAIVED by <id> until <date>` on every run. It is never hidden.
5. **Warning.** From 7 days before expiry, every run carries a warning annotation.
6. **Expired.** On `expires_at` the file becomes invalid and the gate fails on every pull request and on the daily run of `main`, until the entry is removed.
7. **Close.** Fix the finding and delete the entry. If the fix is not ready, a new waiver with a new ID and fresh approval is needed; an existing waiver cannot be extended past 30 days.

## What is rejected

- Missing or unknown fields, quoted dates, malformed IDs or references.
- Wildcards or catch-all values in `rule`, `path` or `resource`; a `path` that is a directory.
- A lifetime over 30 days, a `created_at` in the future, an expired waiver.
- `approved_by` equal to `requested_by`.
- Duplicate IDs, or two waivers for the same finding.

A waiver applies only when scanner, rule, path and resource all match a finding exactly. The same CVE in another package or another file is still blocked.

## Secrets

Gitleaks scans the full git history, so revoking a credential does not make the finding go away. A secret waiver only buys time to clean up, and it requires all of the following, tracked in the `reference` ticket:

1. **Revoke immediately.** The credential is revoked or rotated before the waiver is requested. A waiver is never approved for a live credential.
2. **Investigate exposure.** Check where the credential was usable and whether it was used (for an AWS key, CloudTrail), and record the outcome in the ticket.
3. **Resolve the finding before the waiver expires**, in one of two ways:
   - remove the secret from repository history (rewrite, force-push, and have clones and forks refreshed); or
   - migrate the finding to the explicitly approved exact-fingerprint baseline for the revoked secret, described below.
4. **Remove the temporary waiver afterwards.** Once the scan is clean, delete the entry.

Renewing a secret waiver again and again is not the intended remediation. A second waiver for the same secret should be treated as a missed clean-up, not as routine.

### The exact-fingerprint baseline

Removal from history is preferred. Sometimes a rewrite is deliberately ruled out, for example because released tags or audit evidence depend on the existing commit SHAs. Temporary waivers must not be abused to cover that case. Migrate the finding to a separately reviewed baseline instead:

- A `.gitleaksignore` file at the repository root, which Gitleaks reads natively.
- One line per finding, holding the exact Gitleaks fingerprint (`commit:file:rule:line`). No patterns, paths or rules.
- Only for credentials that are permanently revoked and whose exposure investigation is closed, with the ticket in a comment above the line.
- Each addition is its own pull request, approved by the platform team (`.gitleaksignore` is in CODEOWNERS).

This is a permanent, exact exception and is the only one for secrets. The file does not exist in this repository because nothing has needed it. Test fixtures and other false positives are a rule-tuning matter (a reviewed Gitleaks allowlist), not a waiver or a baseline entry.

## Approval and signing

- Approval is the CODEOWNER review on the pull request. `.github/CODEOWNERS` assigns `/waivers/`, `/scripts/` and `/.github/` to the platform team.
- While any waiver or break-glass entry exists, CI checks that the last commit to change `waivers.yaml` is one GitHub reports as verified (signed).
- **Assumption:** production enforces branch protection on `main` with required code-owner review, required signed commits and `security-gates` as a required check. Those are GitHub repository settings and are not implemented in this assessment.
- A detached signature file was considered and not added. Its list of trusted keys would live in the same repository under the same review rule, so it would prove nothing that signed commits and code-owner review do not already prove.

## Commands

```sh
python3 -m pip install -r scripts/requirements.txt
python3 scripts/waivers.py validate                 # schema, scope and expiry
python3 scripts/waivers.py gate --reports reports   # thresholds and waivers against scanner reports
python3 -m unittest discover -s tests -v            # tests for the rules above
```
