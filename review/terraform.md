# Terraform: defects, ranking and fixes

The ranking is by practical exploitability in this environment, meaning how few preconditions an attacker needs. Scanner severity is not used.

- Fixed configuration: `terraform/review-remediate.tf`
- Supplied version (reconstructed from the brief): `tests/fixtures/terraform/bad/main.tf`
- Prevention: Trivy built-in checks plus the custom checks in `policies/terraform/`, run by the IaC gate in `security-gates.yml` and tested by `tests/test_policies.py`

| Rank | Defect | Precondition for an attacker | Why it ranks here | Fix | Prevented by | Threat |
|---|---|---|---|---|---|---|
| 1 | DB security group allows 5432 from `0.0.0.0/0` | None | With rank 2 it puts the customer database on the internet, with only a password in the way. Even once the instance is private, it still admits every other tenant in the shared cluster and anything else in the VPC. | Ingress only from the accounts-api pod security group. | `ACCT-TF-001` (custom): no public CIDR on 5432 | T2, T3 |
| 2 | `publicly_accessible = true` | None, given rank 1 | Gives the instance a public address. Not reachable without rank 1, which is why it is second. | `false`, in a private subnet group. | `AWS-0180` (built-in) | T2 |
| 3 | `storage_encrypted = false` | AWS credentials with RDS snapshot permissions | A snapshot can be shared or copied out of the account with no key standing in the way. | Encrypted with a customer-managed KMS key with rotation. | `AWS-0080` (built-in) | T2, T5 |
| 4 | CloudTrail `include_global_service_events = false` | AWS credentials | IAM and STS activity, such as role assumption, new access keys and policy changes, is not recorded. That is exactly the activity T5 depends on seeing. | `true` | `ACCT-TF-005` (custom) | T5 |
| 5 | CloudTrail `is_multi_region_trail = false` | AWS credentials | Anything done in another region is unrecorded, including copying a snapshot there. | `true` | `ACCT-TF-004` (custom) | T5 |
| 6 | `backup_retention_period = 0` | Database or AWS access, and destructive intent | Not a way in. It makes any destructive event unrecoverable: no automated backups and no point-in-time recovery. | 35 days, the RDS maximum. | `ACCT-TF-002` (custom) | T2 |
| 7 | `skip_final_snapshot = true` | Permission to delete the instance | One stolen privileged credential or one mistaken `terraform destroy` removes the database with no copy left. | Final snapshot required, plus `deletion_protection`. | `ACCT-TF-003` (custom) | T2, T5 |
| 8 | CloudTrail `enable_log_file_validation = false` | Write access to the log bucket | Lowest: it only matters once an attacker can already alter log files. It removes the proof that logs were not tampered with. | `true` | `AWS-0016` (built-in) | T5 |

## Why custom checks were needed

The existing Trivy IaC gate was kept; no second scanner was added. Trivy's built-in checks at HIGH or CRITICAL catch three of the eight defects. They do not flag PostgreSQL open to the internet at all (the built-in ingress check covers SSH and RDP only), they rate backup retention and multi-region as MEDIUM, and they have no check for the final snapshot or global service events. The five custom checks close those gaps inside Trivy, so findings flow through the same gate and waiver process.

## Also changed, and why

- **CloudTrail `kms_key_id`.** Not a supplied defect. Trivy flags a trail without a customer-managed key as HIGH (`AWS-0015`), and passing a key is a one-line change that protects the audit trail, so it was fixed.
- **`deletion_protection = true`** as part of the final-snapshot fix.

## Remediation notes for a live database

- Storage encryption cannot be switched on in place. It needs a snapshot, an encrypted copy of the snapshot, and a restore.
- The pod security group assumes security groups for pods are enabled on the cluster. Using the shared node security group instead would let every tenant reach the database.
