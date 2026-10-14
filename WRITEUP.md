# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

My primary framework is **SOC 2 (Trust Services Criteria)**. Acme is a telehealth company, so HIPAA is the more
obvious fit for PHI, and I considered it. I chose SOC 2 for two reasons. First, the enterprise customer asking for
assurance will want a SOC 2 Type II report, and Type II is about controls operating over time. That is exactly what a
pipeline that produces signed evidence on every push demonstrates. Second, I work in in-house GRC, so SOC 2 is the
framework I can reuse in my day job. The starter's gap list already maps each gap to a SOC 2 criterion, and the
encryption, access, and logging work also supports HIPAA, so choosing SOC 2 does not leave the PHI story empty.

## Control coverage

I closed six of the eight starter gaps, each in Terraform and each guarded by a Rego policy so it cannot quietly return.

| Gap | SOC 2 | Terraform fix | Policy |
|---|---|---|---|
| GAP-01 S3 not under our key | CC6.1 | SSE-KMS with our rotating CMK on `uploads` | `cc6_1_s3_kms` |
| GAP-02 DynamoDB default key | CC6.1 | `server_side_encryption` with our CMK | `cc6_1_dynamodb_cmk` |
| GAP-03 no TLS-only policy | CC6.7 | Bucket policy denying `aws:SecureTransport = false` | `cc6_7_s3_tls` |
| GAP-04 no versioning | A1.2 | `aws_s3_bucket_versioning` on `uploads` | `a1_2_s3_versioning` |
| GAP-05 Lambda outside VPC | CC6.6 | `vpc_config` on private subnets, locked-down security group, S3 and DynamoDB gateway endpoints in the starter's VPC | `cc6_6_lambda_vpc` |
| GAP-07 over-broad IAM | CC6.3 | `dynamodb:PutItem`, `s3:PutObject` on `uploads/*`, and the PHI key only | `cc6_3_iam_wildcards` |
| GAP-06 no DLQ/concurrency/X-Ray | CC7.2 | Not done | None |
| GAP-08 no API logging/throttling/WAF | CC7.2 | Not done | None |

Beyond the gaps, the baseline adds a separate evidence KMS key, an Object Lock evidence vault, a multi-region
CloudTrail with log file validation, and two GitHub OIDC roles. The OSCAL component records each control with the real
Terraform addresses and links to signed evidence, and marks CC7.2 and the CI role requirement as `partial` rather than
claiming more than I built.

## Design decisions

- **Region: us-east-1.** It is the starter's default and I had no residency requirement, so I stayed consistent.
- **Object Lock: GOVERNANCE, 90 days.** COMPLIANCE is the stronger tamper-resistance claim, but nothing, not even root,
  can delete evidence, and I was iterating in a sandbox. GOVERNANCE still blocks ordinary deletion and requires a
  deliberate privileged bypass. I would move to COMPLIANCE for production evidence. 90 days also fixed an earlier lab
  failure where 1-day retention had expired before the grader could check it.
- **Apply on merge to main, no manual approval.** The gate runs on the exact plan that gets applied, and branch
  protection requires the `grc-gate` check for everyone, including admins, so a failing change cannot merge. I accepted
  the risk that a merged change deploys immediately. With a team I would add a manual approval for production.
- **Single AWS account.** Acceptable for 30 days. The weakness is that an account compromise could reach the vault. A
  separate vault account is what I would do next.
- **Closed gaps in both layers.** Every gap I fixed is fixed in Terraform and also blocked by policy. Terraform makes the
  system compliant today. The policy makes the pipeline refuse a change that reopens the gap.
- **Two OIDC roles.** Pull requests can only assume a read-only plan role. Only runs on `main` can assume the apply role.
  A malicious or broken PR can preview changes but cannot deploy.

## How the pipeline produces evidence

A pull request runs Plan and Policy check as the read-only role. If the gate fails, the check goes red and branch
protection refuses the merge (PR #2, run 38460904696, message: `[SOC2 A1.2] aws_s3_bucket.uploads: S3 bucket does not
have versioning enabled ... Remediation: add aws_s3_bucket_versioning with status = Enabled`). After a merge to `main`,
the same job re-plans, re-checks, applies that plan, builds a bundle (plan, apply log, gate results, run metadata),
signs it with Cosign keyless through GitHub OIDC, and uploads bundle, SHA-256, signature, and a receipt to the vault.
Run **38462035721** verifies with `scripts/verify-evidence.sh`: `Verified OK` and `CHAIN INTACT`. Run 38459132716, the
first merge, also verified.

One thing that went wrong along the way is worth recording. After I moved the Lambda into the VPC and encrypted
DynamoDB with my own key, the app returned Internal Server Error. The Lambda role had no permission to use the new key.
I added KMS permission and tightened the role at the same time, and the test passed after IAM propagated. It confirmed
that the smoke test belongs in the pipeline, because hardening can break a working app.

## Trade-offs and limitations

- The apply role has `AdministratorAccess`. It is only reachable from `main`, but it should be a scoped custom policy.
- Pull request runs do not write evidence to the vault, because the PR role is read-only by design. Evidence is
  produced for merges to `main`, and failed PRs are evidenced by the run log and the blocked merge.
- The IAM policy check can only read policy documents whose values are known at plan time, so a brand-new role created
  in the same plan could slip past it. The TLS check recognizes bucket policies built from `aws_iam_policy_document`
  data sources, and policies built other ways would fail closed (a false positive, not a miss).
- The verify script accepts any signer identity from GitHub Actions (`--certificate-identity-regexp '.*'`). It should pin
  the identity to this repository's workflow.
- The Terraform state bucket was created with the AWS CLI so Terraform could use it. It uses SSE-S3 and has no state locking.
- SOC 2 has no official OSCAL catalog, so I wrote a small Acme catalog of the six criteria I implemented, with
  paraphrased titles and an illustrative NIST 800-53 crosswalk. It is honest but not an AICPA artifact.
- Evidence links in the OSCAL point at a specific run and expire with the 90-day retention (around mid-January 2027).

## What I'd do with another sprint

1. Replace the admin apply role with a scoped policy, and add environment protection for production applies.
2. Move the evidence vault to a separate AWS account and test COMPLIANCE mode.
3. Close GAP-06 and GAP-08 (API access logging, throttling, WAF, Lambda DLQ and tracing) and add policies for them.
4. Pin the Cosign verification identity, and add a policy covering Object Lock and CloudTrail settings.
5. Run `trestle validate` in the pipeline and have the pipeline update the OSCAL evidence links automatically.

## What I didn't get to

GAP-06 and GAP-08 are open. I did not add Security Hub or AWS Config to the capstone, though I used them in an earlier
lab. There is no separate vault account, no CMK on the state bucket, and no automated refresh of OSCAL evidence links.
