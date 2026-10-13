package compliance.cc6_1_s3_kms_test

import data.compliance.cc6_1_s3_kms as pol
import rego.v1

bucket := {"type": "aws_s3_bucket", "name": "uploads"}

good_sse := {
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "aws:kms"},
			"kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
		}]}],
	},
}

aes_sse := {
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
	},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_kms_bucket_passes if {
	count(pol.deny) == 0 with input as with_resources([bucket, good_sse])
}

test_no_encryption_config_fails if {
	some msg in pol.deny with input as with_resources([bucket])
	contains(msg, "CC6.1")
	contains(msg, "aws_s3_bucket.uploads")
}

test_sse_s3_default_fails if {
	some msg in pol.deny with input as with_resources([bucket, aes_sse])
	contains(msg, "CC6.1")
}
