package compliance.a1_2_s3_versioning_test

import data.compliance.a1_2_s3_versioning as pol
import rego.v1

bucket := {"type": "aws_s3_bucket", "name": "uploads"}

versioning(status) := {
	"type": "aws_s3_bucket_versioning",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"versioning_configuration": [{"status": {"constant_value": status}}],
	},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_versioned_bucket_passes if {
	count(pol.deny) == 0 with input as with_resources([bucket, versioning("Enabled")])
}

test_no_versioning_fails if {
	some msg in pol.deny with input as with_resources([bucket])
	contains(msg, "A1.2")
	contains(msg, "aws_s3_bucket.uploads")
}

test_suspended_versioning_fails if {
	some msg in pol.deny with input as with_resources([bucket, versioning("Suspended")])
	contains(msg, "A1.2")
}
