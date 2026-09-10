# policies/gap07_iam_least_privilege_aws.rego
# METADATA
# title: GAP-07 - Lambda IAM role must be scoped, not wildcarded
# description: "The Lambda inline policy must not grant dynamodb:* or s3:* — actions and resources must be scoped."
# custom:
#   control_id: AC.L2-3.1.5
#   framework: cmmc-level-2
#   severity: critical
package compliance.gap07_aws

import rego.v1

deny contains msg if {
	planned := planned_values("aws_iam_role_policy.lambda_inline")
	doc := json.unmarshal(planned.policy)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	some action in as_array(stmt.Action)
	endswith(action, ":*")
	msg := sprintf("[GAP-07] aws_iam_role_policy.lambda_inline: wildcard action %q — scope to specific required actions", [action])
}

deny contains msg if {
	planned := planned_values("aws_iam_role_policy.lambda_inline")
	doc := json.unmarshal(planned.policy)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	some resource in as_array(stmt.Resource)
	resource == "*"
	msg := "[GAP-07] aws_iam_role_policy.lambda_inline: Resource \"*\" — scope to the specific table/bucket ARNs"
}

as_array(x) := x if is_array(x)
as_array(x) := [x] if not is_array(x)

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
