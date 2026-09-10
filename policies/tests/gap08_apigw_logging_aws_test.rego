# policies/tests/gap08_apigw_logging_aws_test.rego
package compliance.gap08_test

import rego.v1
import data.compliance.gap08_aws

missing_all := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_apigatewayv2_stage.default", "values": {}},
]}}}

fully_configured := {"planned_values": {"root_module": {"resources": [
	{"address": "aws_apigatewayv2_stage.default", "values": {
		"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:apigw"}],
		"default_route_settings": [{"throttling_rate_limit": 100}],
	}},
]}}}

test_missing_all_fails if {
	msgs := gap08_aws.deny with input as missing_all
	count(msgs) == 2
}

test_fully_configured_passes if {
	count(gap08_aws.deny) == 0 with input as fully_configured
}
