# Break-glass

One emergency path for shipping a fix while production is down and a security gate is red. It makes the SAST, SCA and IaC gates non-blocking for at most 24 hours. It does not switch anything off: every scanner still runs and every finding is still reported.

## When it may be used

Only for a declared production incident where the fix cannot wait for a finding to be remediated. Not for deadlines, flaky tests or convenience. For a single known finding outside an incident, use a normal waiver (`waivers/README.md`).

## How to invoke it

1. **Incident.** Create the incident or ticket and get its ID. Break-glass without an incident ID is rejected by CI.
2. **Emergency pull request.** The fix goes in a pull request that also adds one entry under `break_glass` in `waivers/waivers.yaml`:

   ```yaml
   break_glass:
     - id: BG-2026-001
       incident: INC-42
       reason: Production outage; the rollback fix must ship before the dependency fix lands.
       invoked_by: "@alice"
       approved_by: "@bob"
       invoked_at: 2026-10-02T14:00:00Z
       expires_at: 2026-10-03T02:00:00Z
   ```

3. **Second authorised person.** A different platform-team member approves the pull request. They are the `approved_by`; the validator rejects self-approval, and CODEOWNERS requires platform approval for this file.
4. **Merge.** Normally the gate now reports each finding as `BYPASS by BG-… (INC-…)` and passes, and the pull request merges in the usual way.
5. **Emergency override, only if needed.** If the required check still cannot go green in time (for example a scanner failed to run, which the gate never bypasses, or GitHub Actions itself is degraded), a named maintainer may use the repository's audited branch-protection emergency override to merge. Steps 1 to 3 must already be done, and the maintainer notes the incident ID on the pull request. The override is not for merging past a secret finding.
6. **GitHub records it.** The approving review, the workflow run with its bypassed findings, and any override are recorded by GitHub (see the audit trail below). `build.yml` then builds, signs and attests the image exactly as normal.
7. **Expiry.** The entry expires within 24 hours of `invoked_at`. From then CI is red until it is removed.
8. **Follow-up.** Remediation and a retrospective follow; see "Afterwards".

## Limits enforced by `scripts/waivers.py`

- **Time-limited.** `expires_at` may be at most 24 hours after `invoked_at`. Only one entry may exist at a time.
- **Secrets are never bypassed.** A production fix never needs to commit a credential, so the secret gate still blocks.
- **Scanner failures are never bypassed.** Break-glass bypasses findings, not the absence of a scan. A scanner that failed to run, or a missing, unreadable or malformed report, still blocks.
- **Waiver validation is never bypassed.** A malformed or expired file still fails.
- **Expiry is loud.** Once expired, the entry makes the gate fail on every pull request and on the daily run of `main` until it is removed.

## Audit trail

| Where | What it records |
|---|---|
| Git history of `waivers/waivers.yaml` | Who invoked, who approved, the incident, the exact window; in signed commits |
| Pull request | The approving review and its timestamp |
| Workflow run | A warning annotation "BREAK-GLASS ACTIVE", and each bypassed finding in the log and job summary |
| GitHub audit log and pull request timeline | The merge, who used the emergency override and when, and any change to branch protection |
| CloudTrail, tooling account | The build role assumed by the workflow on `main`, and the image push to ECR |
| Sigstore transparency log | The signature binding the emergency image digest to its commit |

## Afterwards

- **Within 24 hours:** remove the entry in a pull request that links the incident. CI stays red until this is done.
- **Within 5 working days:** every bypassed finding is either fixed or covered by a normal waiver with its own ticket.
- **Retrospective:** the incident review records why break-glass was needed and whether a gate or threshold should change.

## What is not a break-glass path

Disabling or editing the workflow, removing the required check, changing branch protection, pushing directly to `main`, or using the emergency override without an incident, a break-glass entry and a second approval. Each of these silently removes a control; they are visible in the GitHub audit log and should be treated as an incident in their own right.
