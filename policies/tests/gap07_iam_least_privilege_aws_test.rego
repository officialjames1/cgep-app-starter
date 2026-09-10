# policies/tests/gap07_iam_least_privilege_aws_test.rego
package compliance.gap07_test

import rego.v1
import data.compliance.gap07_aws

wildcard_action := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_iam_role_policy.lambda_inline", "values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/intake"}],
	})}},
]}}}

wildcard_resource := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_iam_role_policy.lambda_inline", "values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "*"}],
	})}},
]}}}

scoped_policy := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_iam_role_policy.lambda_inline", "values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
			"Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/intake",
		}],
	})}},
]}}}

test_wildcard_action_fails if {
	some msg in gap07_aws.deny with input as wildcard_action
	contains(msg, "GAP-07")
}

test_wildcard_resource_fails if {
	some msg in gap07_aws.deny with input as wildcard_resource
	contains(msg, "GAP-07")
}

test_scoped_policy_passes if {
	count(gap07_aws.deny) == 0 with input as scoped_policy
}
