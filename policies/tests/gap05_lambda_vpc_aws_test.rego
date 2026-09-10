# policies/tests/gap05_lambda_vpc_aws_test.rego
package compliance.gap05_test

import rego.v1
import data.compliance.gap05_aws

no_vpc_config := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {}},
]}}}

empty_subnets := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {"vpc_config": [{"subnet_ids": []}]}},
]}}}

with_subnets := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_lambda_function.intake", "values": {"vpc_config": [{"subnet_ids": ["subnet-0123456789abcdef0"]}]}},
]}}}

test_no_vpc_config_fails if {
	some msg in gap05_aws.deny with input as no_vpc_config
	contains(msg, "GAP-05")
}

test_empty_subnets_fails if {
	some msg in gap05_aws.deny with input as empty_subnets
	contains(msg, "GAP-05")
}

test_with_subnets_passes if {
	count(gap05_aws.deny) == 0 with input as with_subnets
}
