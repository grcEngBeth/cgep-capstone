package compliance.cc6_7_s3_tls_test

import data.compliance.cc6_7_s3_tls as pol
import rego.v1

bucket := {"type": "aws_s3_bucket", "name": "uploads"}

bucket_policy := {
	"type": "aws_s3_bucket_policy",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"policy": {"references": ["data.aws_iam_policy_document.uploads_tls.json", "data.aws_iam_policy_document.uploads_tls"]},
	},
}

tls_doc := {
	"mode": "data",
	"type": "aws_iam_policy_document",
	"name": "uploads_tls",
	"expressions": {"statement": [{
		"effect": {"constant_value": "Deny"},
		"condition": [{
			"test": {"constant_value": "Bool"},
			"variable": {"constant_value": "aws:SecureTransport"},
			"values": {"constant_value": ["false"]},
		}],
	}]},
}

allow_only_doc := {
	"mode": "data",
	"type": "aws_iam_policy_document",
	"name": "uploads_tls",
	"expressions": {"statement": [{"effect": {"constant_value": "Allow"}}]},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_tls_bucket_passes if {
	count(pol.deny) == 0 with input as with_resources([bucket, bucket_policy, tls_doc])
}

test_no_bucket_policy_fails if {
	some msg in pol.deny with input as with_resources([bucket])
	contains(msg, "CC6.7")
	contains(msg, "aws_s3_bucket.uploads")
}

test_policy_without_tls_deny_fails if {
	some msg in pol.deny with input as with_resources([bucket, bucket_policy, allow_only_doc])
	contains(msg, "CC6.7")
}
