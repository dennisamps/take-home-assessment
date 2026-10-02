# GitHub Actions OIDC trust policy

`github-oidc-trust-policy.json` is the trust (assume-role) policy for the `accounts-api-github-build` role. JSON cannot carry comments, so the scope is explained here. Traces to T1 in `threat-model.md`.

## What it allows

Exactly one `sub` claim, matched with `StringEquals` (no wildcards):

```
repo:mal/accounts-api:ref:refs/heads/main
```

That is a workflow run in `mal/accounts-api` whose ref is the `main` branch, requesting a token for audience `sts.amazonaws.com`.

## What it denies

| Identity | `sub` it presents | Result |
|---|---|---|
| Any other repository, including other `mal/*` repos | `repo:mal/other:...` | Denied |
| Forks of accounts-api | `repo:someone/accounts-api:...` | Denied |
| Feature branches | `repo:mal/accounts-api:ref:refs/heads/feature-x` | Denied |
| Pull request runs, including PRs that edit a workflow | `repo:mal/accounts-api:pull_request` | Denied |
| Tag pushes | `repo:mal/accounts-api:ref:refs/tags/v1` | Denied |
| Jobs that declare a GitHub environment | `repo:mal/accounts-api:environment:<name>` | Denied |
| Tokens minted for another audience | `aud` is not `sts.amazonaws.com` | Denied |

## What it does not do

- It does not pin the workflow file. Any workflow on `main` can assume the role, so the scope is only as strong as branch protection on `main`. Branch protection and required review are assumed GitHub repository controls and are not implemented as part of this assessment.
- `123456789012` is a placeholder for the tooling/build account, and the GitHub OIDC provider is assumed to exist already in that account.
- It grants nothing in the production account. The role it guards is push-only to one ECR repository; deployment would use a separate role with its own trust policy.
