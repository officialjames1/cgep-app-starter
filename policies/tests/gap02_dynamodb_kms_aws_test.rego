# policies/tests/gap02_dynamodb_kms_aws_test.rego
package compliance.gap02_test

import rego.v1
import data.compliance.gap02_aws

default_key := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_dynamodb_table.intake", "values": {"server_side_encryption": [{"enabled": true}]}},
]}}}

no_sse := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_dynamodb_table.intake", "values": {}},
]}}}

with_cmk := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_dynamodb_table.intake", "values": {"server_side_encryption": [{
		"enabled": true,
		"kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
	}]}},
]}}}

test_no_sse_fails if {
	some msg in gap02_aws.deny with input as no_sse
	contains(msg, "GAP-02")
}

test_default_key_fails if {
	some msg in gap02_aws.deny with input as default_key
	contains(msg, "GAP-02")
}

test_with_cmk_passes if {
	count(gap02_aws.deny) == 0 with input as with_cmk
}
