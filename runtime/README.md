# Runtime detection for accounts-api

One custom Falco rule: `runtime/falco/accounts-api-rules.yaml`, rule **"Unexpected process in accounts-api container"**.

## What it detects

Inside the accounts-api application container only (namespace `accounts-api`, container `accounts-api`), either of:

- a shell, network client, package manager, or cloud or cluster CLI being started (`sh`, `bash`, `curl`, `wget`, `nc`, `ssh`, `apt`, `pip`, `aws`, `kubectl` and similar);
- any binary executed from `/tmp`.

## Why it is specific to this workload

- accounts-api runs one long-lived application process. It never starts a shell or a tool, so every match is an intruder or a mistake worth knowing about. That is what makes it safe to page on.
- The corrected manifest has a read-only root filesystem and one writable path, `/tmp`. An attacker who brings their own binary has to put it there, and nothing legitimate runs from there.
- It is not a copy of Falco's default "Terminal shell in container" rule. That rule needs an interactive terminal and applies to every container in the cluster. A shell opened through an application exploit has no terminal, so the default rule misses it; and a cluster-wide shell rule would page for every team's debugging session.

## Threat mapping

| Threat | How the rule relates |
|---|---|
| T2 | A shell or tool in this container is the visible sign that the pod has been exploited. |
| T3 | Reconnaissance and tooling are the first steps before moving to other tenants or the node. Catching them here is early. |
| T5 | The threat is activity that goes unnoticed. This is the one place where a compromise of accounts-api produces an immediate, high-confidence signal. |

## Severity

`CRITICAL`. It pages. The expected rate in normal operation is zero.

## Alert payload

Falco emits JSON. Besides `time`, `rule`, `priority`, `hostname` (the node) and `tags`, the alert carries:

| Field | Use to the responder |
|---|---|
| `proc.name`, `proc.cmdline`, `proc.exepath` | What ran, with arguments, and from where |
| `proc.pname`, `proc.pcmdline`, `proc.aname[2]` | Parent and grandparent: was it spawned by the application (exploit) or by `kubectl exec` (a person) |
| `user.name`, `user.uid` | Should be UID 10001; UID 0 means the hardening has been defeated |
| `proc.tty` | Non-zero means an interactive session |
| `proc.cwd` | Working directory |
| `k8s.ns.name`, `k8s.pod.name`, `container.name`, `container.id` | Exactly which pod to contain |
| `container.image.repository`, `container.image.digest` | Whether the running image is the signed one |

## Where the alert goes

```
Falco (DaemonSet on every node)
   -> Falcosidekick
        -> SIEM / central alerting      every event, for search and correlation
        -> PagerDuty                    priority CRITICAL only -> on-call platform engineer
```

- **Owner and first responder:** the on-call platform engineer.
- **Secondary:** the accounts-api service owner, paged by the responder for application context.
- **Escalation:** if node compromise is suspected (step 2), the responder declares an incident; the break-glass process in `break-glass.md` applies to any emergency change.

## First three responder actions

### Step 1: contain the pod without destroying evidence

Do not delete the pod during initial containment; it is the evidence.

```sh
kubectl -n accounts-api label pod <pod> quarantine=true app-
kubectl cordon <node>
```

The first command does two things: it adds the label `quarantine=true`, and the trailing `app-` (the label key followed by a minus sign) removes the pod's normal `app=accounts-api` label. The second cordons the node so no new pods land on it.

Removing the `app` label takes the pod out of the accounts-api Service, so it receives no more traffic, and out of every allow NetworkPolicy, because they all select `app=accounts-api`. Only the namespace's `default-deny-ingress` and `default-deny-egress` policies still apply to it, so it can neither be reached nor reach anything. It also leaves the Deployment, which starts a clean replacement. The pod itself keeps running for inspection, and `quarantine=true` marks it for the responders.

### Step 2: decide whether this is a pod compromise or a node compromise

Look at:

- the pod: `kubectl -n accounts-api get pod <pod> -o yaml` and its logs, and the alert's parent process chain;
- Falco events from the same node in the SIEM, especially any from other containers or from the host itself;
- the Kubernetes audit log for anything done by the pod's service account or by `exec` into the pod;
- CloudTrail for the pod's IAM role session: calls outside its three permitted actions, and bursts of `AccessDenied`;
- the egress proxy access log for denied destinations.

Activity confined to the container, as UID 10001, is a pod compromise. UID 0, events from the host, or other tenants' containers on that node behaving oddly point to the node.

### Step 3: rotate what was exposed and replace from known-good state

- Rotate the two secrets the pod could read (database credential, KYC API key) and revoke the role's active sessions.
- Confirm the Deployment is running the signed digest (`cosign verify`, see the top-level README), then roll it.
- If the node is suspect: snapshot its volume for evidence, drain it and terminate it so the node group replaces it.
- Only after evidence is captured, delete the quarantined pod (`kubectl -n accounts-api delete pod -l quarantine=true`).

## Assumptions and limits

- Falco and Falcosidekick are installed and run by the platform team; PagerDuty routing by priority is configured there. This repository supplies the rule, not the deployment.
- The container image starts the application directly, with no shell wrapper, and the manifest has no `exec` probes. If either changes, the rule needs an exception.
- The rule was checked with `falco --validate` (Falco 0.45.0). It has not been fired on a live cluster.
- A name list can be evaded by running a renamed tool from a path other than `/tmp`; with a read-only root filesystem there is no such path, but a tool already present in the image under an unlisted name would not match. The stricter form of this rule is "any process other than the application binary", which becomes possible once the application's own process name is fixed.
