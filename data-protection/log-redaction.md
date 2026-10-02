# Log redaction specification for accounts-api

What accounts-api may write to its logs, which layer enforces it, and what still leaks. Traces to threat-model.md T4 (customer data leaving through logs) and T5 (logs must stay useful for investigation). The machine-readable lists are in `data-protection/log-policy.yaml`.

## Principle

Redaction by allowlist, not by pattern. The application decides what is safe to log and emits only that; it does not log everything and try to scrub it afterwards. Pattern matching is a second, defensive stage and is not relied on.

## What is never logged, and what is omitted

| Data | Treatment | Layer |
|---|---|---|
| Request and response bodies | Not logged by default. No debug switch enables them in production. | 1 |
| `Authorization` headers, cookies, session tokens | Never logged | 1, checked at 2 |
| Database credentials, KYC API keys, any Secrets Manager value | Never logged | 1, checked at 2 |
| Arbitrary headers and query parameters | Not logged. Only the route template is recorded, never the raw URL. | 1 |
| Customer name | Omitted | 1 |
| Email, phone number, IBAN | Omitted; masked if one slips through | 1, backstop at 2 |
| Card last-four | Omitted. Four digits cannot be recognised by a pattern, so stage 1 is the only control. | 1 |
| Customer ID, account ID and other identifiers | Omitted. If user-level correlation is operationally required, a keyed pseudonym is logged instead (`subject_ref`). | 1 |
| Free-text log messages | Not used. Events carry an enumerated `event` code, because interpolated message strings are how personal data usually reaches logs. | 1 |

## What may be logged

Only these fields: `timestamp`, `level`, `event`, `request_id`, `route` (template), `method`, `status`, `latency_ms`, `service`, `version`, `image_digest`, `pod`, `namespace`, `error_class`, `error_code` and, where required, `subject_ref`.

`subject_ref` is HMAC-SHA-256 of the customer ID under a key held in Secrets Manager and not available to log readers. It lets one customer's requests be tied together without revealing who the customer is.

## Which layer does what

| Stage | Where | What it does |
|---|---|---|
| 1. Application logging layer | Inside the accounts-api process, **before the event leaves the process** | Structured JSON logging through one logger that accepts only the allowlisted fields. Anything else is dropped at the call site. A unit test in the application asserts that the logger rejects unknown fields and that handlers emit only allowlisted ones. |
| 2. Central log pipeline / SIEM ingest | After collection, before storage and indexing | Defensive. Drops any field not on the allowlist, drops and alerts on any event with a forbidden key, and applies the patterns in `log-policy.yaml` (email, IBAN, card number, E.164 phone, bearer token, JWT, AWS access key ID) to string values, masking matches and raising an alert. A stage 2 hit is treated as a bug in stage 1. |
| 3. Storage | Log groups | Encrypted, restricted read access, fixed retention (threat-model.md T4). Limits who sees whatever the first two stages miss. |

Stage 1 is the control. Stage 2 exists because developers make mistakes and libraries log on their own.

## What still leaks

This design reduces what logs reveal; it does not make them harmless.

- **Timing and volume.** Timestamps and request frequency show when and how much a service, and with `subject_ref` a customer, is active.
- **Routes.** The route accessed shows what was done: a KYC check, an account closure.
- **Outcome.** Status code and latency reveal success, failure and sometimes the code path taken. Payload size would too if it were recorded, which is why it is not on the allowlist.
- **Edge metadata.** CloudFront and the ALB record source IP and user-agent in their own logs. If retained there, they identify people regardless of what accounts-api logs.
- **Pseudonyms correlate.** `subject_ref` hides who the customer is but ties their activity together, and anyone holding the key or a list of customer IDs can reverse it.
- **Error codes reveal business state.** An enumerated code such as `kyc_rejected` or `insufficient_funds` is customer information even without a name next to it.
- **The KYC destination is visible.** Egress proxy logs show that, and when, accounts-api called the KYC provider.
- **Developer error.** A developer can still add a sensitive field to the allowlist, or log through a path that bypasses the logger. Schema tests and review of allowlist changes reduce this; they do not remove it.
- **Patterns miss things.** Stage 2 cannot recognise names, addresses, card last-four, national-format phone numbers or free text, and it can mask harmless values that look like a match. Regex filtering does not make logging safe; it catches some mistakes.
- **Other emitters.** Dependencies, the language runtime, crash dumps and the proxy or sidecars write their own output outside the application logger.

## Encryption

Customer data in RDS and secrets in Secrets Manager are encrypted at rest with customer-managed AWS KMS keys, with key administration separated from workload use; TLS protects data in transit. This reduces exposure from stolen storage/snapshots and unauthorised direct access to encrypted backing data, but does not protect data from an authorised or compromised running accounts-api process.

The accounts-api database client is required to use TLS. Production should also enable the RDS PostgreSQL `rds.force_ssl` parameter so non-TLS clients are rejected.

## Assumptions

- accounts-api's code is not in this repository, so stage 1 is a specification for the application team, with `log-policy.yaml` as the contract. Stage 2 is a specification for the platform team's log pipeline.
- The patterns are verified against the examples in `log-policy.yaml` with Python's regex engine. They avoid lookarounds so they port to RE2-style engines, but they have not been run in a real pipeline.
- Key administration is separated in the key policy for the secrets key (`terraform/secrets.tf`). For the RDS key the workload role simply has no permission on it.
- `rds.force_ssl` is not configured in this repository's Terraform, so TLS to the database is a client requirement here, not something the server enforces.
