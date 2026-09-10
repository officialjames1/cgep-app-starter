# policies/gap05_lambda_vpc_aws.rego
# METADATA
# title: GAP-05 - Intake Lambda must run inside the starter's VPC
# description: "The intake Lambda must specify vpc_config with subnet_ids, not run in the default Lambda environment."
# custom:
#   control_id: SC.L2-3.13.1
#   framework: cmmc-level-2
#   severity: high
package compliance.gap05_aws

import rego.v1

deny contains msg if {
	not has_vpc_config
	msg := "[GAP-05] aws_lambda_function.intake: no vpc_config with subnet_ids — Lambda is running in the default environment"
}

has_vpc_config if {
	planned := planned_values("aws_lambda_function.intake")
	vc := planned.vpc_config[_]
	count(vc.subnet_ids) > 0
}

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
