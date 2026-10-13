# policies/cc6_6_lambda_vpc.rego
# METADATA
# title: CC6.6 - Lambda functions run inside the VPC (GAP-05)
# description: "Every aws_lambda_function needs a vpc_config block with subnet_ids."
# custom:
#   control_id: CC6.6
#   controls:
#     - "CC6.6"
#   framework: soc2
#   severity: high
#   remediation: "Add vpc_config with the private subnet_ids and a locked-down security group to the Lambda function."
package compliance.cc6_6_lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not in_vpc(r)
	msg := sprintf(
		"[SOC2 CC6.6] aws_lambda_function.%s: function runs outside the VPC. Remediation: add vpc_config with private subnet_ids and a hardened security group.",
		[r.name],
	)
}

in_vpc(r) if {
	some v in r.expressions.vpc_config
	v.subnet_ids
}
