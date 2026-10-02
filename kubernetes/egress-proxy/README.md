# Egress control for accounts-api

accounts-api needs to reach exactly one destination on the internet: the KYC provider's API. Everything else outbound to the internet is denied.

## Architecture

```
                         namespace accounts-api                       namespace egress-system
                       +------------------------+                    +-----------------------+
                       |  accounts-api pod      |   TCP 3128         |  egress proxy (Squid) |    TCP 443
   default-deny-egress |  HTTPS_PROXY=proxy ----+------------------> |  allowlist:           | -----------> api.kyc-provider.example
   for every pod       |                        |                    |  CONNECT to one host  |
                       |                        |                    |  on port 443, else 403|
                       +---+--------+-------+---+                    +-----------------------+
                           |        |       |
                 UDP/TCP 53|   5432 |       | 443 / 80
                           v        v       v
                       cluster    RDS     VPC endpoints (AWS APIs),
                       DNS      subnets   Pod Identity Agent
```

Two layers, each doing the part it can do properly:

| Layer | File | What it enforces |
|---|---|---|
| Kubernetes NetworkPolicy | `kubernetes/accounts-api-network-policy.yaml` | Default-deny egress for every pod in the namespace. The accounts-api pods may reach only cluster DNS, the egress proxy, the database subnets, the VPC endpoint subnet and the Pod Identity Agent. No rule allows an internet address. |
| Egress proxy allowlist | `kubernetes/egress-proxy/squid.conf` | One permitted request: an HTTPS tunnel (`CONNECT`) to `api.kyc-provider.example` on port 443. Any other hostname, subdomain, port, or plain HTTP gets a 403 and is logged. |
| Proxy isolation | `kubernetes/egress-proxy/proxy-network-policy.yaml` | Only accounts-api pods may connect to the proxy. The proxy may reach the internet on 443 only, never private or link-local addresses. |

The workload is pointed at the proxy with `HTTPS_PROXY` in `kubernetes/accounts-api.yaml`. Private dependencies are listed in `NO_PROXY` and go direct.

## Why a proxy, and not a NetworkPolicy rule for the KYC provider

Standard Kubernetes NetworkPolicy matches IP addresses and pod labels. It has no notion of a DNS name. The only way to express "the KYC provider" in it is a list of IP ranges, and a third-party API behind a CDN does not publish stable ranges: the list would be wrong within weeks, and on a shared CDN the same addresses serve thousands of other sites. So the NetworkPolicy does not attempt it. It restricts where packets can go (the proxy), and the proxy, which sees the hostname in the `CONNECT` request, restricts which hostname.

## What it does not stop

| Not stopped | Why |
|---|---|
| Malicious requests sent to the legitimate KYC hostname | The allowlist checks the destination, not the content. The tunnel is end-to-end TLS; the proxy cannot see inside it. |
| Compromise of the KYC provider itself | A trusted destination that turns hostile is still an allowed destination. |
| Data exfiltration disguised as KYC traffic | An attacker in the pod can put customer data in a request to the KYC API, for example in a field of a legitimate-looking call. If the provider shares a CDN with other sites, the hostname inside the tunnel could also differ from the one the proxy approved. |
| DNS or proxy compromise | The proxy resolves the hostname. Whoever controls its DNS answers, or the proxy itself, controls where the tunnel goes. DNS queries are also a slow exfiltration channel through cluster DNS, which must stay allowed. |
| Any destination reachable through a misconfigured proxy | The control is exactly as strong as `squid.conf`. A broader ACL, a leading dot on the hostname, or a second tenant's allowlist merged in, silently widens it for accounts-api too. |
| Abuse of the private dependencies | The database, the AWS endpoints and the stream are reachable by design. What the pod can do with them is limited by the IAM policy and the database grants, not by this control. |
| Other tenants, and pods on the host network | NetworkPolicy applies per namespace and does not govern host-network pods. That is the admission policies' job. |

What reduces these: the runtime rule in `runtime/` (a shell or tool in the pod), the proxy access log in the SIEM (every denied destination is evidence of an attempt), the KYC provider's own request logging and API-key scoping, and code-owner review on `squid.conf`.

## Ingress, in the same file

`kubernetes/accounts-api-network-policy.yaml` also holds the ingress side, which is a separate concern (T3, lateral movement from other tenants): `default-deny-ingress` for every pod in the namespace, and one allow rule from the ALB subnets to the application port. The ALB subnets and port are placeholders, and the rule assumes the ALB uses IP targets; the assumption is written above the rule.

## Assumptions

- The cluster enforces NetworkPolicy (the VPC CNI network policy agent, or Calico or Cilium).
- The platform team runs the egress proxy in `egress-system`, highly available, with `squid.conf` mounted and its log shipped to the SIEM. The proxy Deployment is not part of this submission; the allowlist and its NetworkPolicy are the specification for it.
- `api.kyc-provider.example` and the three private CIDRs are placeholders.
- AWS APIs are reached through VPC interface endpoints, and pod credentials come from the EKS Pod Identity Agent at `169.254.170.23`.
- The application's HTTP client honours `HTTPS_PROXY` and `NO_PROXY`.

## How it was tested

- `tests/test_runtime_and_egress.py` checks that no NetworkPolicy rule allows an internet address, that the proxy is the only external route, that the allowlist is one exact hostname on 443 followed by deny-all, and that Squid accepts the file.
- With `EGRESS_LIVE_TEST=1` it also runs the real configuration in a container, with `example.com` standing in for the KYC hostname, and sends requests through it: the allowed hostname on 443 is tunnelled; another hostname, a subdomain, another port and plain HTTP all get 403.
- The same test file checks the ingress policies: default-deny for every pod, and exactly one allow rule, from the ALB subnets only.
- The NetworkPolicies were not applied to a live cluster.
