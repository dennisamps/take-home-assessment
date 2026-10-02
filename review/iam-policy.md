# Pod identity IAM policy: defects and rewrite

- Rewritten policy: `iam/accounts-api-pod-policy.json`
- Supplied version: `tests/fixtures/iam/bad.json`
- Prevention: `policies/iam/least_privilege.rego` (check `ACCT-IAM-001`), run by the IaC gate and tested by `tests/test_policies.py`

## One-line comparison

The new policy denies everything except reading two named secrets, decrypting them with one key through Secrets Manager, and reading one stream; the original allowed every AWS action except `iam:DeleteRole` and `iam:DeleteUser` on every resource, including creating administrator users, reading every secret in the account and deleting the database.

## Defects, ranked by exploitability

| Rank | Defect | Why it ranks here | Threat |
|---|---|---|---|
| 1 | `Allow` with `NotAction` on `Resource: "*"` | This is administrator access minus two delete actions. From code execution in one pod (T2), an attacker can create an IAM user or access key, attach `AdministratorAccess`, and own the whole account. It turns one application bug into the loss of everything in the account. | T2, T5 |
| 2 | `secretsmanager:GetSecretValue` and `kms:Decrypt` on `Resource: "*"` | Every secret and every KMS key in the account, including other teams'. Serious, but a subset of rank 1. | T2, T3 |

## What the rewritten policy grants

| Statement | Grants | Why this and no more |
|---|---|---|
| `ReadOwnSecretsOnly` | `GetSecretValue` and `DescribeSecret` on the database credential and the KYC API key | The two secrets the system context establishes. `DescribeSecret` is needed by the Secrets Store CSI Driver that mounts them (Section 6). The `-??????` suffix matches the six characters Secrets Manager appends to a secret's ARN; it matches one secret, not a group. |
| `DecryptOwnSecretsThroughSecretsManagerOnly` | `kms:Decrypt` on one key | Only when called by Secrets Manager and only for accounts-api secrets, so the key cannot be used to decrypt anything else directly. |
| `ConsumeAccountEventsStreamOnly` | Four read actions on one Kinesis stream | The message stream from the system context, read-only. |

The `NotAction` statement is removed completely. There is no `Resource: "*"` and no wildcard action anywhere in the policy.

## Deliberately not granted

- Nothing for RDS: the application connects over the network with the credential from Secrets Manager, not through IAM.
- Nothing for S3, SQS, DynamoDB, CloudWatch or any IAM action. None is established by the system context, and nothing was added because it might be useful.

## Assumptions

- `111122223333` is a placeholder for the workload/production account, and the KMS key ID is a placeholder.
- The message stream is Kinesis Data Streams. If it is MSK with IAM authentication, the third statement is replaced by the equivalent `kafka-cluster` read actions on the named cluster, topic and group. If the stream does not use IAM authentication, the statement is deleted.
- The secrets use a customer-managed KMS key. If they use the AWS-managed key, the second statement is deleted.
