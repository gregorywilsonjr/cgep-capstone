# Acme Health — CGE-P capstone

Fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter). Primary framework: **HIPAA Security Rule**. Write-up: [`WRITEUP.md`](WRITEUP.md).

AWS CLI profile for this sandbox is `sandbox` (not `default`). Region: `us-east-1`.

## Grader verification

```bash
# 0. Identity
export AWS_PROFILE=sandbox
make creds

# 1. Policies
opa test -v policies

# 2. Terraform + Conftest (remote state in s3://cgep-capstone-tfstate-gregorywilsonjr)
cd terraform && terraform init && terraform plan -out=tfplan && cd ..
bash scripts/policy-gate.sh --workspace terraform
# expect: policy-gate: PASS

# 3. Live API
make test AWS_PROFILE=sandbox
# expect: {"submission_id":"...","status":"received"}

# 4. OSCAL (compliance-trestle 5.1.x, OSCAL 1.2.1)
# See oscal/README.md for the trestle workspace copy; then:
# trestle validate -t catalog -n hipaa-security-rule
# trestle validate -t profile -n cge-p-minimum
# trestle validate -t component-definition -n acme-health-intake

# 5. Evidence chain (after the first signed Actions run on this repo)
bash scripts/verify-evidence.sh <run_id> \
  --vault acme-health-intake-evidence-a9082633 \
  --profile sandbox
# expect: CHAIN INTACT
```

GitHub variables: `AWS_ROLE_ARN` = `arn:aws:iam::202191080127:role/cgep-capstone-grc-gate`, `EVIDENCE_VAULT` = `acme-health-intake-evidence-a9082633`.

Do not `make destroy`. The evidence vault uses Object Lock **COMPLIANCE / 30 days**.

## Layout

| Path | Layer |
|---|---|
| `terraform/` | Starter workload + KMS, vault, CloudTrail, OIDC, hardening |
| `policies/` | 8 HIPAA Rego policies + tests |
| `scripts/policy-gate.sh` | Conftest wrapper |
| `.github/workflows/grc-gate.yml` | Plan → Policy check → Apply (main) → Sign → Upload |
| `oscal/` | Catalog, profile, component |
