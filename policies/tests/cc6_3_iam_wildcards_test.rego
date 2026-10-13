package compliance.cc6_3_iam_wildcards_test

import data.compliance.cc6_3_iam_wildcards as pol
import rego.v1

policy_input(action) := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": action,
			"Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/example",
		}],
	})},
}]}}}

test_least_privilege_passes if {
	count(pol.deny) == 0 with input as policy_input(["dynamodb:PutItem"])
}

test_service_wildcard_fails if {
	some msg in pol.deny with input as policy_input("dynamodb:*")
	contains(msg, "CC6.3")
	contains(msg, "aws_iam_role_policy.lambda_inline")
}

test_star_action_fails if {
	some msg in pol.deny with input as policy_input(["*"])
	contains(msg, "CC6.3")
}
