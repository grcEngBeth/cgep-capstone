# OSCAL: how the pieces connect

Chain a reviewer can follow: policy -> component -> catalog.

| File | Purpose |
|---|---|
| `catalogs/soc2-tsc-acme.json` | Acme-authored summary catalog of the six SOC 2 criteria this system implements (AICPA publishes no official OSCAL catalog). |
| `profiles/acme-soc2-minimum.json` | Profile selecting those six criteria from the catalog. |
| `components/acme-health-intake.json` | Component definition: what was built, with Terraform addresses as `terraform-resource` props, Rego policy files as `rego-policy` props, and signed evidence links. |

## Evidence links

Each `implemented-requirement` links to a signed bundle in the Object Lock vault
(`s3://<vault>/runs/<run_id>/evidence-<run_id>-<sha>.tar.gz`). Verify one with:

    export EVIDENCE_VAULT=<vault name>
    scripts/verify-evidence.sh <run_id> --profile <aws profile>

Expected last line: `CHAIN INTACT for run <run_id>`.

Bundles are retained for 90 days (GOVERNANCE mode). Before the links go stale,
run the pipeline (any merge to main) and update the `href` values to the new
run ID and file name.
