# policies/gap04_s3_versioning_aws.rego
# METADATA
# title: GAP-04 - S3 uploads bucket must have versioning enabled
# description: "PHI overwrites/deletes must be recoverable via S3 versioning."
# custom:
#   control_id: MP.L2-3.8.9
#   framework: cmmc-level-2
#   severity: high
package compliance.gap04_aws

import rego.v1

deny contains msg if {
	not has_versioning("aws_s3_bucket.uploads")
	msg := "[GAP-04] aws_s3_bucket.uploads: versioning is not enabled"
}

has_versioning(bucket_addr) if {
	v := versioning_for(bucket_addr)
	planned := planned_values(v.address)
	cfg := planned.versioning_configuration[_]
	cfg.status == "Enabled"
}

versioning_for(bucket_addr) := v if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	v := {"address": sprintf("aws_s3_bucket_versioning.%s", [r.name])}
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
