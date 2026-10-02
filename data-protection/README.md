# Secrets delivery for accounts-api

How the database credential gets from its source of truth to the running process, without ever being written to Git, a manifest, a Kubernetes Secret or an environment variable. Traces to threat-model.md T2 (credential blast radius) and T4 (data exposure).

## The path

```
AWS Secrets Manager          secret "accounts-api/db-credentials", encrypted with a customer-managed KMS key
      |                      (terraform/secrets.tf; the value is never written by Terraform)
      v
accounts-api pod identity    EKS Pod Identity -> IAM role -> iam/accounts-api-pod-policy.json
      |                      GetSecretValue and DescribeSecret on two named secrets only; Decrypt only via Secrets Manager
      v
Secrets Store CSI Driver     AWS provider, kubernetes/accounts-api-secrets.yaml (usePodIdentity: "true")
      |                      fetches the secret using the pod's identity, not the node's
      v
Read-only in-memory volume   tmpfs on the node, mounted at /mnt/secrets, readOnly: true
      |                      /mnt/secrets/db-credentials.json
      v
accounts-api process         reads the file named by ACCOUNTS_API_DB_CREDENTIALS_FILE
```

| Step | File | What to check |
|---|---|---|
| Source of truth | `terraform/secrets.tf` | Secret and KMS key are defined; there is no secret version, so no value is in Git or Terraform state |
| How it is refreshed | `kubernetes/secrets-store-csi-driver/values.yaml` | Auto-rotation enabled with a 2-minute poll interval, and no sync to Kubernetes Secrets |
| Who may read it | `iam/accounts-api-pod-policy.json` | Two named secret ARNs, no wildcard resource |
| How it is fetched | `kubernetes/accounts-api-secrets.yaml` | `SecretProviderClass` with secret names only, `usePodIdentity: "true"`, and no `secretObjects` block |
| How it reaches the pod | `kubernetes/accounts-api.yaml` | A `csi` volume mounted `readOnly: true`; the environment holds a file path, not a value |

The KYC API key follows the same path, as the file `/mnt/secrets/kyc-api-key`.

## What this achieves

- **No plaintext in Git or manifests.** The repository holds secret names. `tests/test_secrets_and_logging.py` fails if a Kubernetes Secret, a `secretObjects` block, a secret-bearing environment variable or a Terraform secret value appears.
- **Nothing in etcd.** The value is not synced into a Kubernetes Secret, so a reader of Secrets in the namespace, or of an etcd backup, gets nothing.
- **Not in the environment.** It cannot leak through `/proc/<pid>/environ`, a crash dump of the environment or a child process. The admission policy `disallow-secrets-in-env` keeps it that way.
- **Scoped identity.** The fetch uses the accounts-api pod identity. Another tenant's pod on the same node cannot mount this secret, because its own identity has no permission on it.
- **One audit trail.** Every fetch is a `GetSecretValue` event in CloudTrail under the accounts-api role (T5).

## Rotation and the running process

```
Secrets Manager rotation  ->  CSI reconciler updates the mounted file  ->  application re-reads the file, or the pods are rolled
```

- **The driver does not refresh secrets by default.** Out of the box it fetches a secret once, when the pod starts. Auto-rotation (the driver's reconciler) must be enabled explicitly: `enableSecretRotation: true` with `rotationPollInterval: 2m`, as specified in `kubernetes/secrets-store-csi-driver/values.yaml`. With that set, the reconciler re-fetches each mounted secret about every two minutes and rewrites the file.
- **The driver never restarts or signals the application.** A new value reaches the running process only when the process re-reads the file. accounts-api is therefore required to read the credential file whenever it opens a database connection or sees an authentication failure.
- **Where neither can be relied on, the pods are rolled.** A new pod always mounts the current value, with or without auto-rotation. That is what the emergency procedure in `rotation.md` does.

## What it does not protect against

- A compromised accounts-api process can read the mounted file and use the credential. This design limits how many places the credential exists; it does not hide it from the workload that needs it.
- The same pod identity could call Secrets Manager directly for the same two secrets. The blast radius is those two secrets, as in Section 4.
- Anyone with `exec` into the pod, or root on the node, can read the file while the pod runs.

## Assumptions

- The platform team runs the Secrets Store CSI Driver and the AWS provider on the cluster, at a version that supports EKS Pod Identity, with the settings in `kubernetes/secrets-store-csi-driver/values.yaml`. Auto-rotation is not a driver default; if it is left off, a rotated secret reaches a pod only when the pod restarts.
- The secret is a JSON document with `username`, `password`, `host`, `port` and `dbname`, the format the Secrets Manager rotation function maintains.
- The application reads its credentials from the two file paths in its environment.
- The accounts-api database client is required to use TLS. Production should also enable the RDS PostgreSQL `rds.force_ssl` parameter so non-TLS clients are rejected.
- The Terraform configures the secret and rotation schedule; the production rotation Lambda implementing the alternating-user strategy is specified but not deployed/tested in this assessment.
