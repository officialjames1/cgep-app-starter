# policies/gap06_lambda_resilience_aws.rego
# METADATA
# title: GAP-06 - Intake Lambda must have reserved concurrency, a DLQ, and active X-Ray tracing
# description: "Failures must be contained (DLQ, reserved concurrency) and observable (active X-Ray tracing)."
# custom:
#   control_id: SI.L2-3.14.6
#   framework: cmmc-level-2
#   severity: medium
package compliance.gap06_aws

import rego.v1

deny contains msg if {
	not has_reserved_concurrency
	msg := "[GAP-06] aws_lambda_function.intake: reserved_concurrent_executions is not set"
}

deny contains msg if {
	not has_dlq
	msg := "[GAP-06] aws_lambda_function.intake: no dead_letter_config target is set"
}

deny contains msg if {
	not has_active_tracing
	msg := "[GAP-06] aws_lambda_function.intake: no active X-Ray tracing (tracing_config) is set"
}

has_reserved_concurrency if {
	planned := planned_values("aws_lambda_function.intake")
	planned.reserved_concurrent_executions != null
}

has_dlq if {
	planned := planned_values("aws_lambda_function.intake")
	count(planned.dead_letter_config) > 0
}

has_active_tracing if {
	planned := planned_values("aws_lambda_function.intake")
	tc := planned.tracing_config[_]
	tc.mode == "Active"
}

planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
