# policies/tests/gap06_lambda_resilience_aws_test.rego
package compliance.gap06_test

import rego.v1
import data.compliance.gap06_aws

missing_all := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {}},
]}}}

inactive_tracing := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {
		"reserved_concurrent_executions": 5,
		"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:dlq"}],
		"tracing_config": [{"mode": "PassThrough"}],
	}},
]}}}

fully_configured := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {
		"reserved_concurrent_executions": 5,
		"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:dlq"}],
		"tracing_config": [{"mode": "Active"}],
	}},
]}}}

test_missing_all_fails if {
	msgs := gap06_aws.deny with input as missing_all
	count(msgs) == 3
}

test_inactive_tracing_fails if {
	some msg in gap06_aws.deny with input as inactive_tracing
	contains(msg, "GAP-06")
}

test_fully_configured_passes if {
	count(gap06_aws.deny) == 0 with input as fully_configured
}
