# Workload manifest: defects, ranking and fixes

Reviewed as a production workload in a shared, multi-tenant EKS cluster. The ranking is by how easily each defect is exploited here, starting from the realistic position in threat-model.md T2: an attacker with code execution inside the accounts-api container. Scanner severity is not used.

- Fixed manifest: `kubernetes/accounts-api.yaml`
- Supplied version (reconstructed from the brief): `tests/fixtures/kubernetes/bad.yaml`
- Prevention: `policies/kubernetes/` (Kyverno), tested by `tests/test_policies.py`

| Rank | Defect | Why it ranks here | Fix | Prevented by | Threat |
|---|---|---|---|---|---|
| 1 | Role grants `*` on secrets, pods and configmaps, with the service account token mounted | No escape needed. One API call with the mounted token reads every Secret in the namespace, and `create pods` lets the attacker start a pod of their choosing. Works on any node and any runtime. | Role and RoleBinding deleted: the workload does not call the Kubernetes API. Token no longer mounted. | `restrict-rbac` | T2, T3 |
| 2 | `hostNetwork: true` | hostNetwork places the pod in the node network namespace, can undermine workload network isolation, and increases exposure to node-local services such as IMDS. | Removed. | `disallow-host-namespaces` | T2, T3 |
| 3 | hostPath mount of `/var/log` | Gives the container every tenant's container logs on that node, readable immediately. As root it can also alter or delete them, which damages the audit trail. | Removed. Logs go to stdout; the only writable path is an `emptyDir` at `/tmp`. | `disallow-host-path` | T3, T4, T5 |
| 4 | hostPath mount of `/var/run/docker.sock` | On a node running Docker this is immediate root on the node and every pod on it. Ranked fourth only because, assuming standard modern EKS nodes using containerd, the socket most likely does not exist and the mount is inert today. If any node group still runs Docker, this is rank 1. | Removed. | `disallow-host-path` | T3 |
| 5 | `runAsUser: 0` with no hardening (`privileged: false` alone is not hardening) | Not an entry point, but an amplifier: root with default capabilities is what makes ranks 2 to 4 fully usable, and it widens any kernel or runtime escape. | Runs as UID 10001 with `runAsNonRoot`, `allowPrivilegeEscalation: false`, all capabilities dropped, read-only root filesystem, seccomp `RuntimeDefault`. | `require-hardened-containers` | T2, T3 |
| 6 | Image tag `:latest` | Not exploitable from inside the pod; it needs write access to the registry. It means nobody can say which build is running, and a registry write becomes a silent code change at the next restart. It also contradicts Section 2, where the pipeline never pushes `latest`. | Referenced by digest, as built and signed by `build.yml`. | `require-image-digest` | T1, T2 |
| 7 | `envFrom` `secretRef` | Lowest: it needs code execution or a crash dump first, and rank 1 already gave the attacker the secrets. It copies the whole Secret into the environment of the process and every child process. | Removed. The secret comes from Secrets Manager using the pod identity (`iam/accounts-api-pod-policy.json`) and is mounted read-only as a file by the Secrets Store CSI Driver (Section 6). | `disallow-secrets-in-env` | T2, T4 |

## Also changed, and why

- **Memory limit and CPU/memory requests.** Justified by the shared cluster: without them one tenant can starve the others on a node. No policy was added for this because it was not a supplied defect.
- **`automountServiceAccountToken: false`** on the ServiceAccount and the pod. This is how the Role in rank 1 was reachable, so it is part of that fix.

- **`HTTPS_PROXY` and `NO_PROXY`**, added in Section 5 for the egress control.
- **The read-only `secrets` volume**, added in Section 6 for secrets delivery.

Nothing else was added. Image signature verification at admission and a pod security group are deliberately not in this file; they are not among the supplied defects.

## Scope of the policies

- All six policies are enforced in the `accounts-api` namespace, which this team owns.
- The host-namespace and hostPath checks also run in audit mode for every other tenant namespace, because a host-level escape by any tenant endangers every tenant on that node. Modes and promotion criteria are in `policies/kubernetes/README.md`.
