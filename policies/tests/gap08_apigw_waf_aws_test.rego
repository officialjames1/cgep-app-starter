# policies/tests/gap08_apigw_waf_aws_test.rego
package compliance.gap08_waf_test

import rego.v1
import data.compliance.gap08_waf_aws

no_waf := {"planned_values": {"root_module": {"resources": []}}}

with_waf := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_wafv2_web_acl_association.default", "type": "aws_wafv2_web_acl_association", "values": {}},
]}}}

test_no_waf_fails if {
	some msg in gap08_waf_aws.deny with input as no_waf
	contains(msg, "GAP-08-WAF")
}

test_with_waf_passes if {
	count(gap08_waf_aws.deny) == 0 with input as with_waf
}
