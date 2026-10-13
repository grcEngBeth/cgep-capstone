# policies/cc6_1_dynamodb_cmk.rego
# METADATA
# title: CC6.1 - DynamoDB tables use a customer-managed KMS key (GAP-02)
# description: "Every aws_dynamodb_table needs server_side_encryption enabled with kms_key_arn set."
# custom:
#   control_id: CC6.1
#   framework: soc2-tsc
#   severity: high
#   remediation: "Add a server_side_encryption block with enabled = true and kms_key_arn = our CMK ARN."
package compliance.cc6_1_dynamodb_cmk

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	not cmk_encrypted(r)
	msg := sprintf(
		"[SOC2 CC6.1] aws_dynamodb_table.%s: table uses the AWS-owned default key. Remediation: add server_side_encryption { enabled = true, kms_key_arn = our CMK }.",
		[r.name],
	)
}

cmk_encrypted(r) if {
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	sse.kms_key_arn
}
