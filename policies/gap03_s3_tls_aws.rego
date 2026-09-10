# policies/gap03_s3_tls_aws.rego
# METADATA
# title: GAP-03 - S3 uploads bucket must deny non-TLS requests
# description: "The uploads bucket policy must include an explicit Deny statement for requests where aws:SecureTransport is false."
# custom:
#   control_id: SC.L2-3.13.8
#   framework: cmmc-level-2
#   severity: high
package compliance.gap03_aws

import rego.v1

deny contains msg if {
	not has_tls_deny("aws_s3_bucket.uploads")
	msg := "[GAP-03] aws_s3_bucket.uploads: no bucket policy statement denies requests where aws:SecureTransport is false"
}

has_tls_deny(bucket_addr) if {
	pol := policy_for(bucket_addr)
	planned := planned_values(pol.address)
	doc := json.unmarshal(planned.policy)
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	cond := stmt.Condition.Bool["aws:SecureTransport"]
	cond == "false"
}

policy_for(bucket_addr) := pol if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	pol := {"address": sprintf("aws_s3_bucket_policy.%s", [r.name])}
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
