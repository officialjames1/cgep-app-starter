# policies/tests/gap03_s3_tls_aws_test.rego
package compliance.gap03_test

import rego.v1
import data.compliance.gap03_aws

config_with_policy := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket_policy", "name": "uploads",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}}},
]}}}

no_policy_resource := {"configuration": {"root_module": {"resources": []}}}

policy_without_deny := object.union(config_with_policy, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_policy.uploads", "values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}],
	})}},
]}}})

policy_with_deny := object.union(config_with_policy, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_policy.uploads", "values": {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
			"Condition": {"Bool": {"aws:SecureTransport": "false"}},
		}],
	})}},
]}}})

test_no_policy_resource_fails if {
	some msg in gap03_aws.deny with input as no_policy_resource
	contains(msg, "GAP-03")
}

test_policy_without_deny_fails if {
	some msg in gap03_aws.deny with input as policy_without_deny
	contains(msg, "GAP-03")
}

test_policy_with_deny_passes if {
	count(gap03_aws.deny) == 0 with input as policy_with_deny
}
