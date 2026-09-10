# policies/tests/gap04_s3_versioning_aws_test.rego
package compliance.gap04_test

import rego.v1
import data.compliance.gap04_aws

config_with_versioning := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket_versioning", "name": "uploads",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}}},
]}}}

no_versioning_resource := {"configuration": {"root_module": {"resources": []}}}

versioning_disabled := object.union(config_with_versioning, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_versioning.uploads", "values": {"versioning_configuration": [{"status": "Suspended"}]}},
]}}})

versioning_enabled := object.union(config_with_versioning, {"planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket_versioning.uploads", "values": {"versioning_configuration": [{"status": "Enabled"}]}},
]}}})

test_no_versioning_resource_fails if {
	some msg in gap04_aws.deny with input as no_versioning_resource
	contains(msg, "GAP-04")
}

test_versioning_disabled_fails if {
	some msg in gap04_aws.deny with input as versioning_disabled
	contains(msg, "GAP-04")
}

test_versioning_enabled_passes if {
	count(gap04_aws.deny) == 0 with input as versioning_enabled
}
