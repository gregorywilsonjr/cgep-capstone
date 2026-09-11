# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

The primary framework is the **HIPAA Security Rule**. This workload is a telehealth Patient Intake API that stores ePHI in DynamoDB and S3. HIPAA is the regulation that applies because of that data, not because it is fashionable. SOC 2 Type II would be the better story for an enterprise customer's continuous-control narrative, and CMMC Level 2 would be the better story for a federal pilot, but neither is why this system exists. Acme is a 50-person telehealth company. The first GRC engineer here has to show that encryption at rest is under our key, that transmission is TLS-only, and that we can reconstruct who did what. Those are 164.312(a)(2)(iv), 164.312(e)(1), and 164.312(b).

NIST does not publish an official OSCAL catalog for HIPAA. The component's `control-implementation.source` is `../catalogs/hipaa-security-rule.json` in this repo: a 164.x subset written so trestle can validate, aligned to [NIST SP 800-66 Rev. 2](https://csrc.nist.gov/pubs/sp/800/66/r2/final).

## Control coverage

| Gap | HIPAA | Terraform | Policy |
|---|---|---|---|
| GAP-01 S3 SSE-S3 not CMK | 164.312(a)(2)(iv) | `aws_s3_bucket_server_side_encryption_configuration.uploads` with `aws:kms` | `gap01_s3_cmk.rego` |
| GAP-02 DynamoDB AWS-owned key | 164.312(a)(2)(iv) | `aws_dynamodb_table.intake` `server_side_encryption` + PITR | `gap02_ddb_cmk.rego` |
| GAP-03 no TLS deny | 164.312(e)(1) | `aws_s3_bucket_policy.uploads_tls` (also vault and trail) | `gap03_s3_tls.rego` |
| GAP-04 no versioning | 164.308(a)(7) | `aws_s3_bucket_versioning.uploads` | `gap04_s3_versioning.rego` |
| GAP-05 Lambda not in VPC | 164.312(e)(1) | `vpc_config` on private subnets + VPC endpoints, no NAT, no second VPC | `gap05_lambda_vpc.rego` |
| GAP-06 no DLQ / X-Ray / reserved concurrency | 164.308(a)(7) | SQS DLQ + Active X-Ray. Reserved concurrency omitted (account quota: UnreservedConcurrentExecution floor is 10) | `gap06_lambda_resilience.rego` |
| GAP-07 `dynamodb:*` / `s3:*` | 164.312(a)(1) | PutItem/GetItem and PutObject/GetObject only | `gap07_iam_least_privilege.rego` |
| GAP-08 no API logs / throttle / WAF | 164.312(b) | Access logs + 10 rps throttle. WAF not built | `gap08_apigw_logging.rego` |

## Design decisions

- **Region.** `us-east-1`. Matches the starter default and the lab account. No residency requirement was given.
- **Object Lock.** **COMPLIANCE, 30 days** on `acme-health-intake-evidence-a9082633`. Strongest custody claim I can make in this account. Objects cannot be deleted until retention ends, including by me. The trade-off is operational: a mistaken upload stays.
- **Apply on merge.** `.github/workflows/grc-gate.yml` plans and policy-checks every PR; on push to `main` it applies, then signs and uploads. The GitHub role `cgep-capstone-grc-gate` has AdministratorAccess for 30 days in this sandbox. Production would split plan vs apply and drop that managed policy.
- **Single account.** Evidence vault lives in the same account as the API. Cleaner for 30 days; production would isolate the vault so a workload-account compromise cannot rewrite evidence.
- **Terraform vs policy.** Every gap that is a resource misconfiguration is closed in Terraform *and* blocked in Rego so a later PR cannot reintroduce it. Reserved concurrency and WAF are the exceptions, documented below.
- **VPC.** Lambda uses the starter VPC. Private subnets had no route table; I added one plus gateway endpoints (S3, DynamoDB) and interface endpoints (KMS, logs, SQS, X-Ray). No NAT. Interface endpoints cost about $7/month each while they sit.
- **OIDC.** This account already has a GitHub OIDC provider from Lab 4.3. The capstone role is a new role that trusts `gregorywilsonjr/cgep-capstone` (classic and immutable `sub`). It does not reuse `cgep-grc-gate`.
- **Remote state.** `s3://cgep-capstone-tfstate-gregorywilsonjr` with DynamoDB lock `cgep-capstone-tf-lock`, created outside this root module so the state bucket is not managing itself.

## How the pipeline produces evidence

1. Open a PR. `grc-gate` runs **Plan** then **Policy check**.
2. Merge to `main`. The same workflow **Apply**s the saved plan, then **Sign**s the evidence bundle (Cosign keyless) and **Upload**s it to the COMPLIANCE vault.
3. An assessor runs `scripts/verify-evidence.sh <run_id> --vault acme-health-intake-evidence-a9082633 --profile sandbox` and should see `CHAIN INTACT`.

The first signed object does not exist until this repo's workflow has run against GitHub OIDC. OSCAL `links[rel=evidence].href` still says `PENDING` until that receipt exists. That is the one grader-facing hole left before submit.

## Trade-offs and what I'd do with another sprint

- Request a Lambda concurrency quota increase and then set `reserved_concurrent_executions`.
- Put an AWS WAF WebACL on the HTTP API (GAP-08 leftover).
- Split the GitHub apply role off AdministratorAccess.
- Move the vault to a second account.
- Six-year CloudWatch retention instead of 90 days.

## What I didn't get to

Reserved concurrency (quota). WAF. Cognito on `/intake` (explicitly out of scope in WORKLOAD.md). Patient-data lifecycle (delete/export). A 6-year audit-log retention period.
