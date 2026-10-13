# policies/cc6_3_iam_wildcards.rego
# METADATA
# title: CC6.3 - IAM policies grant no wildcard actions (GAP-07)
# description: "No aws_iam_role_policy or aws_iam_policy may Allow the * action or a service-wide service:* action."
# custom:
#   control_id: CC6.3
#   controls:
#     - "CC6.3"
#   framework: soc2
#   severity: high
#   remediation: "Replace wildcard actions with the specific actions the code needs, for example dynamodb:PutItem."
package compliance.cc6_3_iam_wildcards

import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy"}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type in policy_types
	doc := json.unmarshal(r.values.policy)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Allow"
	some action in as_array(stmt.Action)
	is_wildcard(action)
	msg := sprintf(
		"[SOC2 CC6.3] %s: IAM policy allows wildcard action %s. Remediation: list only the specific actions the workload needs.",
		[r.address, action],
	)
}

is_wildcard(action) if action == "*"

is_wildcard(action) if endswith(action, ":*")

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)
