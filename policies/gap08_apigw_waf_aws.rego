# policies/gap08_apigw_waf_aws.rego
# METADATA
# title: GAP-08 (deferred portion) - API Gateway stage should be protected by WAF
# description: "Detects missing WAFv2 association. NOT enforced in the CI gate: AWS WAFv2 does not support direct association with HTTP APIs (apigatewayv2) — only REST APIs (v1), ALB, Cognito, AppSync, App Runner. Documented as an accepted platform limitation in OSCAL."
# custom:
#   control_id: AU.L2-3.3.1
#   framework: cmmc-level-2
#   severity: informational
package compliance.gap08_waf_aws

import rego.v1

deny contains msg if {
	count(waf_associations) == 0
	msg := "[GAP-08-WAF] no aws_wafv2_web_acl_association found — informational only, HTTP APIs do not support direct WAF association"
}

waf_associations contains addr if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_wafv2_web_acl_association"
	addr := r.address
}
