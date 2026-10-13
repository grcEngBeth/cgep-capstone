# policies/a1_2_s3_versioning.rego
# METADATA
# title: A1.2 - S3 buckets have versioning enabled (GAP-04)
# description: "Every aws_s3_bucket needs an aws_s3_bucket_versioning resource with status Enabled."
# custom:
#   control_id: A1.2
#   framework: soc2-tsc
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning for the bucket with versioning_configuration status = Enabled."
package compliance.a1_2_s3_versioning

import rego.v1

deny contains msg if {
	some bucket in bucket_addrs
	not versioned(bucket)
	msg := sprintf(
		"[SOC2 A1.2] %s: S3 bucket does not have versioning enabled, so overwrites are unrecoverable. Remediation: add aws_s3_bucket_versioning with status = Enabled.",
		[bucket],
	)
}

bucket_addrs contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

versioned(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some v in r.expressions.versioning_configuration
	v.status.constant_value == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
