package compliance.cc6_1_dynamodb_cmk_test

import data.compliance.cc6_1_dynamodb_cmk as pol
import rego.v1

good_table := {
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
	}]},
}

bad_table := {
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"hash_key": {"constant_value": "submission_id"}},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_cmk_table_passes if {
	count(pol.deny) == 0 with input as with_resources([good_table])
}

test_default_key_table_fails if {
	some msg in pol.deny with input as with_resources([bad_table])
	contains(msg, "CC6.1")
	contains(msg, "aws_dynamodb_table.intake")
}
