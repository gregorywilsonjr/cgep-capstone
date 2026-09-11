# OSCAL

HIPAA Security Rule subset for the Acme Health intake wrap.

| File | Role |
|---|---|
| [`catalogs/hipaa-security-rule.json`](catalogs/hipaa-security-rule.json) | 164.x controls this component claims. Not an official NIST catalog; aligned to SP 800-66 Rev. 2. |
| [`profiles/cge-p-minimum.json`](profiles/cge-p-minimum.json) | Selects those five control IDs. |
| [`components/acme-health-intake.json`](components/acme-health-intake.json) | What Terraform actually built. Evidence `href`s point at run `34551829023` in `s3://acme-health-intake-evidence-a9082633`. |

`compliance-trestle` 5.1.x expects a trestle workspace, not these paths as-is:

```bash
trestle init -loc
mkdir -p catalogs/hipaa-security-rule profiles/cge-p-minimum \
  component-definitions/acme-health-intake
cp oscal/catalogs/hipaa-security-rule.json catalogs/hipaa-security-rule/catalog.json
cp oscal/profiles/cge-p-minimum.json profiles/cge-p-minimum/profile.json
# in the copied profile, set imports[0].href to
# trestle://catalogs/hipaa-security-rule/catalog.json
cp oscal/components/acme-health-intake.json \
  component-definitions/acme-health-intake/component-definition.json
trestle validate -t catalog -n hipaa-security-rule
trestle validate -t profile -n cge-p-minimum
trestle validate -t component-definition -n acme-health-intake
```
