package compliance.cc6_6_lambda_vpc_test

import data.compliance.cc6_6_lambda_vpc as pol
import rego.v1

in_vpc_fn := {
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{
		"subnet_ids": {"references": ["aws_subnet.private"]},
		"security_group_ids": {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]},
	}]},
}

no_vpc_fn := {
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"runtime": {"constant_value": "python3.12"}},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_vpc_lambda_passes if {
	count(pol.deny) == 0 with input as with_resources([in_vpc_fn])
}

test_lambda_outside_vpc_fails if {
	some msg in pol.deny with input as with_resources([no_vpc_fn])
	contains(msg, "CC6.6")
	contains(msg, "aws_lambda_function.intake")
}
