# policies/cc6_1_s3_kms.rego
# METADATA
# title: CC6.1 - S3 buckets use SSE-KMS with a customer key (GAP-01)
# description: "Every aws_s3_bucket needs an SSE configuration using aws:kms with a KMS key we own."
# custom:
#   control_id: CC6.1
#   framework: soc2-tsc
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration for the bucket with sse_algorithm aws:kms and kms_master_key_id set to our CMK."
package compliance.cc6_1_s3_kms

import rego.v1

deny contains msg if {
	some bucket in bucket_addrs
	not kms_encrypted(bucket)
	msg := sprintf(
		"[SOC2 CC6.1] %s: S3 bucket is not encrypted with SSE-KMS using a customer key. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm aws:kms and kms_master_key_id = our CMK.",
		[bucket],
	)
}

bucket_addrs contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

kms_encrypted(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some rule in r.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm.constant_value == "aws:kms"
	d.kms_master_key_id
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
