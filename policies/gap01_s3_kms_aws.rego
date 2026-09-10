# policies/gap01_s3_kms_aws.rego
# METADATA
# title: GAP-01 - S3 uploads bucket must use customer-managed KMS key
# description: "The uploads bucket must be encrypted with SSE-KMS using a customer-managed key, not the AWS-managed SSE-S3 default."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-level-2
#   severity: critical
package compliance.gap01_aws

import rego.v1

deny contains msg if {
	not has_kms_encryption("aws_s3_bucket.uploads")
	msg := "[GAP-01] aws_s3_bucket.uploads: missing or incomplete SSE-KMS encryption with a customer-managed key"
}

has_kms_encryption(bucket_addr) if {
	sse := sse_for(bucket_addr)
	planned := planned_values(sse.address)
	rule := planned.rule[_]
	sse_default := rule.apply_server_side_encryption_by_default[_]
	sse_default.sse_algorithm == "aws:kms"
	sse_default.kms_master_key_id != null
	sse_default.kms_master_key_id != ""
}

sse_for(bucket_addr) := sse if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	sse := {"address": sprintf("aws_s3_bucket_server_side_encryption_configuration.%s", [r.name])}
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
