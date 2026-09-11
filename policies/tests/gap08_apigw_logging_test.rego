# policies/tests/gap08_apigw_logging_test.rego
package compliance.gap08_apigw_logging_test

import rego.v1
import data.compliance.gap08_apigw_logging

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {
		"access_log_settings": [{"destination_arn": {"references": ["aws_cloudwatch_log_group.apigw.arn"]}}],
		"default_route_settings": [{"throttling_rate_limit": {"constant_value": 10}}],
	},
}]}}}

bad := {"configuration": {"root_module": {"resources": [{
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {},
}]}}}

test_good if { count(gap08_apigw_logging.deny) == 0 with input as good }

test_bad if {
	count(gap08_apigw_logging.deny) == 2 with input as bad
}
