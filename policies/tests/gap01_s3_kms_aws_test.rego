# policies/tests/gap01_s3_kms_aws_test.rego
package compliance.gap01_test

import rego.v1
import data.compliance.gap01_aws

config_with_sse := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket_server_side_encryption_configuration", "name": "uploads",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}}},
]}}}

no_sse_resource := {"configuration": {"root_module": {"resources": []}}}

sse_aes256 := object.union(config_with_sse, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}]}},
]}}})

sse_kms_no_key := object.union(config_with_sse, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "aws:kms"}}]}},
]}}})

sse_kms_with_key := object.union(config_with_sse, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": "aws:kms",
			"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
		}]}]}},
]}}})

test_no_sse_resource_fails if {
	some msg in gap01_aws.deny with input as no_sse_resource
	contains(msg, "GAP-01")
}

test_sse_s3_fails if {
	some msg in gap01_aws.deny with input as sse_aes256
	contains(msg, "GAP-01")
}

test_kms_no_key_fails if {
	some msg in gap01_aws.deny with input as sse_kms_no_key
	contains(msg, "GAP-01")
}

test_kms_with_key_passes if {
	count(gap01_aws.deny) == 0 with input as sse_kms_with_key
}
