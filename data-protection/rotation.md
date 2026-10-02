# Credential rotation for accounts-api

Every long-lived credential accounts-api holds, how often it rotates, and how to rotate it in an emergency. Traces to threat-model.md T2 (limit how long a stolen credential is useful) and T5 (know whether it was used).

| Credential | Source of truth | Normal interval | Emergency target |
|---|---|---|---|
| Database credential | Secrets Manager, `accounts-api/db-credentials` | 30 days, scheduled | **15 minutes or less** |
| KYC provider API key | Secrets Manager, `accounts-api/kyc-api-key` | 90 days, or the provider's maximum if shorter | **30 minutes or less**, where the provider offers self-service rotation |
| AWS credentials | None stored. Short-lived, issued by EKS Pod Identity | Refreshed automatically | No key to rotate; revoke sessions in minutes |

The emergency targets are design targets from the step timings below. They have not been measured in a drill.

**Implementation status.** The Terraform configures the secret and rotation schedule; the production rotation Lambda implementing the alternating-user strategy is specified but not deployed/tested in this assessment.

**How any rotation reaches the process.** Secrets Manager rotation, then the CSI reconciler updates the mounted file, then the application re-reads the file or the pods are rolled. The reconciler is not on by default: the Secrets Store CSI Driver must run with auto-rotation enabled and a poll interval of about two minutes (`kubernetes/secrets-store-csi-driver/values.yaml`). If it is off, only a pod restart picks up a new value.

## A. Database credential

**Normal rotation: every 30 days, on a schedule, designed for no downtime.**

- `terraform/secrets.tf` configures the 30-day schedule on the secret and points it at a rotation function. The function itself is specified, not included: see the implementation status above.
- The specified strategy is alternating users. Two database users with identical privileges exist. Each rotation gives the idle user a new password and makes it the current credential. The user the pods are connected as is left untouched and stays valid until the following rotation, 30 days later.
- **How the running service picks it up:** with auto-rotation enabled, the CSI reconciler rewrites `/mnt/secrets/db-credentials.json` within about two minutes. accounts-api reads that file when it opens a database connection, so new connections use the new user and existing connections carry on. The CSI driver does not restart the application; if the application did not re-read the file, it would keep working on the previous user for up to 30 days and fail at the next rotation. Any pod restart in that window also picks up the new value, and authentication failures alert before that deadline.

**Emergency rotation: target 15 minutes or less.** Use when the credential may be exposed.

| Step | Action | Budget |
|---|---|---|
| 1. Create and activate a replacement | `aws secretsmanager rotate-secret --secret-id accounts-api/db-credentials --rotate-immediately`. The idle user gets a new password and becomes current; this also updates Secrets Manager. This step depends on the rotation function being deployed. | 2 min |
| 2. Force the workload onto it | `kubectl -n accounts-api rollout restart deployment/accounts-api` then `kubectl -n accounts-api rollout status deployment/accounts-api`. New pods mount the current value. Do not wait for the CSI poll. | 5 min |
| 3. Verify new connections | Service health and error rate are normal, and `pg_stat_activity` shows connections only from the new user. | 3 min |
| 4. Revoke the old credential | The previous user is still valid under alternating users, so kill it now: as the master user, set a new random password on the previous user and terminate its sessions (`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '<previous user>'`). The next scheduled rotation takes it over again. | 3 min |
| 5. Investigate use | PostgreSQL connection logs for the previous user from unexpected addresses; CloudTrail `GetSecretValue` events on the secret; the egress proxy log. Runs in parallel and continues after the target. | after |

Do steps 1 to 3 before step 4: revoking first would cause an outage.

## B. KYC provider API key

**Normal rotation: every 90 days, or the provider's maximum key lifetime if shorter.** Done by runbook, because the key is issued by the provider, not by AWS.

1. Issue a second key in the provider's console or API. Prefer overlapping keys: both valid at once.
2. Put the new key in Secrets Manager (`aws secretsmanager put-secret-value --secret-id accounts-api/kyc-api-key ...`, from a terminal, never through Git or a ticket).
3. With auto-rotation enabled, the CSI reconciler refreshes the file within about two minutes; accounts-api reads it when it builds a KYC request. Roll the pods if in doubt.
4. Confirm KYC calls succeed with the new key, then revoke the old key at the provider.

If the provider supports only one key at a time, steps 1 and 4 collapse into one and there is a short window in which KYC calls fail. accounts-api must retry those.

**Emergency rotation: target 30 minutes or less, where the provider offers self-service key rotation.**

| Step | Action |
|---|---|
| 1 | Issue a replacement key at the provider |
| 2 | Update Secrets Manager with the new key |
| 3 | `kubectl -n accounts-api rollout restart deployment/accounts-api` and wait for the rollout |
| 4 | Verify KYC calls succeed |
| 5 | Revoke the old key at the provider, then review the provider's request log for use of the old key |

**External dependency:** whether a key can be replaced in minutes, and whether two keys can overlap, is decided by the provider. If rotation needs a support request, the 30-minute target cannot be met and the fallback is to have the provider disable the key, accepting that KYC is unavailable until a new one is issued. This should be confirmed with the provider and written into the contract.

## C. AWS credentials

accounts-api has no long-lived AWS credential. There is no access key to rotate, and none should be created. The pod receives short-lived credentials for its IAM role from EKS Pod Identity, and the SDK refreshes them automatically before they expire.

**During an active compromise**, the concern is credentials already copied out of the pod, which stay valid until they expire even after the pod is gone:

1. Quarantine the pod (`runtime/README.md`), which stops it obtaining fresh credentials for an attacker.
2. Revoke the role's active sessions: attach a deny-all policy to the role conditioned on `aws:TokenIssueTime` earlier than now (the IAM console's "Revoke active sessions"). Stolen credentials stop working at once; replacement pods get credentials issued after that time and are unaffected.
3. Review CloudTrail for the role: calls outside its permitted actions, and any call from an address outside the cluster.

The role can read only the two secrets above and one stream, so after revoking sessions the follow-up is sections A and B.

## Not held by accounts-api

- The RDS master credential is managed and rotated by RDS in Secrets Manager; accounts-api's role cannot read it.
- The pipeline's AWS access is short-lived OIDC (Section 2), and image signing is keyless. Neither has a stored key.
