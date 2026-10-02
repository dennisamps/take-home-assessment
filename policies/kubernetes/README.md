# Admission policies: mode, scope and promotion

Kyverno `ValidatingPolicy` files. Each file states its own mode in `spec.validationActions` (`Deny` is enforce, `Audit` is audit), repeats it in an annotation and a header comment, and `tests/test_policies.py` fails if a file's mode differs from this table.

The rule behind the split: enforce at once where this team owns every manifest and the corrected workload already complies; audit first where about a dozen other teams would otherwise have a deploy blocked without warning.

## Enforce from day one (namespace `accounts-api`)

| Policy | Blocks | Why enforce now |
|---|---|---|
| `disallow-host-namespaces` | `hostNetwork`, `hostPID`, `hostIPC` | Direct path from a pod to the node. Nothing legitimate in the namespace uses it. |
| `disallow-host-path` | Any `hostPath` volume | Direct path to the node filesystem and other tenants' data. |
| `require-hardened-containers` | Root, privileged, privilege escalation, writable root filesystem, undropped capabilities, no seccomp profile | These turn an application bug into a container escape. |
| `restrict-rbac` | Roles with `*`, unnamed access to secrets or configmaps, pod creation | The most exploitable supplied defect. The workload has no Role at all. |
| `require-image-digest` | Images referenced by tag | Only a digest matches what `build.yml` signed. |
| `disallow-secrets-in-env` | `envFrom.secretRef`, `secretKeyRef` | Lower risk than the others, but there is nothing to audit: one team owns every manifest here and it already complies. |

There is no promotion step for these. They are already at the end state.

## Audit first (every namespace except `accounts-api` and `kube-system`)

| Policy | Reports | Why audit first |
|---|---|---|
| `audit-cluster-host-namespaces` | The same check as `disallow-host-namespaces` | One tenant on the host network endangers every tenant on the node (T3), but other teams may run agents that legitimately need it. |
| `audit-cluster-host-path` | The same check as `disallow-host-path` | Log shippers and monitoring agents commonly mount host paths. A day-one deny would break their next deploy. |

Only these two host-escape controls are extended beyond the namespace. The other four are specific to how accounts-api is built and are deliberately not imposed on other teams.

`kube-system` is excluded because the cluster's own networking and storage agents need host access. Platform add-ons in other namespaces, such as the runtime sensor, appear as audit findings and are handled by criterion 3 below.

### Promotion from Audit to Enforce

A policy is promoted by changing `validationActions` from `["Audit"]` to `["Deny"]` in a pull request approved by the platform team. All of the following must be true:

1. **Time in audit:** at least two full weeks, covering each team's normal release cycle.
2. **Zero unexplained violations:** every violation in the Kyverno policy reports has been looked at.
3. **Owners assigned:** each remaining violation has a named owning team and either a fix date or a reviewed, time-limited Kyverno `PolicyException` for a workload that genuinely needs host access.
4. **False positives acceptable:** no violation in the last week was a false positive, meaning the policy flagged something that is in fact safe and expected.
5. **Communicated:** affected teams were told the enforcement date at least one week ahead, with the fix they need to make.

If any criterion fails, the policy stays in audit and the review repeats after a week. Promotion is per policy; one can be enforced while the other waits.

### Residual risk while in audit

Until promotion, another tenant can still run a pod with host access, which is the T3 path into accounts-api. During that period the mitigations are detective (the audit reports and the runtime rule in `runtime/`) and not preventive.
