# policies/gap02_dynamodb_kms_aws.rego
# METADATA
# title: GAP-02 - DynamoDB submissions table must use a customer-managed KMS key
# description: "The intake table must specify server_side_encryption with a customer-managed key, not the AWS-owned default key."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-level-2
#   severity: critical
package compliance.gap02_aws

import rego.v1

deny contains msg if {
	not has_kms_encryption
	msg := "[GAP-02] aws_dynamodb_table.intake: server_side_encryption is not enabled with a customer-managed KMS key"
}

has_kms_encryption if {
	planned := planned_values("aws_dynamodb_table.intake")
	sse := planned.server_side_encryption[_]
	sse.enabled == true
	sse.kms_key_arn != null
	sse.kms_key_arn != ""
}

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
