# policies/gap08_apigw_logging_aws.rego
# METADATA
# title: GAP-08 (enforced portion) - API Gateway stage must have access logging and throttling
# description: "The default stage must configure access_log_settings and default_route_settings (throttling)."
# custom:
#   control_id: AU.L2-3.3.1
#   framework: cmmc-level-2
#   severity: high
package compliance.gap08_aws

import rego.v1

deny contains msg if {
	not has_access_logging
	msg := "[GAP-08] aws_apigatewayv2_stage.default: no access_log_settings configured"
}

deny contains msg if {
	not has_throttling
	msg := "[GAP-08] aws_apigatewayv2_stage.default: no throttling (default_route_settings) configured"
}

has_access_logging if {
	planned := planned_values("aws_apigatewayv2_stage.default")
	count(planned.access_log_settings) > 0
}

has_throttling if {
	planned := planned_values("aws_apigatewayv2_stage.default")
	drs := planned.default_route_settings[_]
	drs.throttling_rate_limit > 0
}

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
