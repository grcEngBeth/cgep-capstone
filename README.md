# Acme Health: SOC 2 governed Patient Intake API

CGE-P capstone. This repo is a fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter).
The starter's workload (API Gateway, Lambda, DynamoDB, S3) is unchanged and still deployable with `make deploy`.
Everything else is the governance layer around it. **Primary framework: SOC 2 Trust Services Criteria.**
Design reasoning is in [`WRITEUP.md`](WRITEUP.md).

## Layout

| Path | What it is |
|---|---|
| `terraform/` | Starter workload plus `kms.tf`, `evidence-vault.tf`, `cloudtrail.tf`, `oidc-trust.tf`, `hardening.tf`, `backend.tf` |
| `policies/` | Six Rego policies (SOC 2 CC6.1 x2, CC6.3, CC6.6, CC6.7, A1.2) with tests in `policies/tests/` |
| `.github/workflows/grc-gate.yml` | One workflow: 1. Plan, 2. Policy check, 3. Apply, 4. Sign, 5. Upload |
| `scripts/` | `policy-gate.sh` (Conftest gate), `verify-evidence.sh` (chain-of-custody check) |
| `oscal/` | SOC 2 summary catalog, profile, and component definition |
| `evidence/oscal/` | `trestle validate` transcript |

## Verify it (grader steps)

**1. Policies pass their tests** (needs `opa`)

    opa test policies

Expect `PASS: 16/16`.

**2. A signed evidence bundle is intact** (needs `aws` CLI, `cosign`, and read access to the vault)

    export EVIDENCE_VAULT=acme-health-intake-evidence-vault-c34bf5d7
    scripts/verify-evidence.sh 38462035721 --profile <your-aws-profile>

Expect `Verified OK` and `CHAIN INTACT for run 38462035721`. The script recomputes the SHA-256, verifies the Cosign
keyless signature against Sigstore, and checks that Object Lock retention is still active (GOVERNANCE, 90 days).
Other runs are listed under `s3://acme-health-intake-evidence-vault-c34bf5d7/runs/`. Every push to `main` adds one.

**3. The gate fails closed** (needs Terraform, Conftest, and AWS credentials)

    cd terraform && terraform init && terraform plan -out=tfplan && cd ..
    scripts/policy-gate.sh --workspace terraform

Expect `PASS`. To see it fail, set the `status` in `aws_s3_bucket_versioning.uploads` to `Suspended` and re-run: the
gate prints `VIOLATION: [SOC2 A1.2] aws_s3_bucket.uploads ...`.

**4. Pull requests in history**

- Green, merged: #1 (baseline), #3 (gate output), #4 (OSCAL)
- Red, blocked and left open: #2 (suspends S3 versioning; merge refused by branch protection, failed run 38460904696)

**5. OSCAL validates** (needs `compliance-trestle`)

    trestle init
    trestle import -f oscal/catalogs/soc2-tsc-acme.json -o soc2-tsc-acme
    trestle import -f oscal/profiles/acme-soc2-minimum.json -o acme-soc2-minimum
    trestle import -f oscal/components/acme-health-intake.json -o acme-health-intake
    trestle validate -a

Run these in a scratch directory (copy `oscal/` there), since `trestle` needs its own workspace.
