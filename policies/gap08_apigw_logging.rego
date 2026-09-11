# policies/gap08_apigw_logging.rego
# METADATA
# title: GAP-08 — API Gateway access logs and throttling
# description: "aws_apigatewayv2_stage must set access_log_settings and throttling."
# custom:
#   framework: hipaa
#   controls: ["164.312(b)"]
#   gap: GAP-08
#   severity: medium
#   remediation: "Add access_log_settings and default_route_settings throttling on the $default stage."
package compliance.gap08_apigw_logging

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	not has_logs(r)
	msg := sprintf("[HIPAA 164.312(b)] aws_apigatewayv2_stage.%s: missing access_log_settings.", [r.name])
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	not has_throttle(r)
	msg := sprintf("[HIPAA 164.312(b)] aws_apigatewayv2_stage.%s: missing default_route_settings throttling.", [r.name])
}

has_logs(r) if count(r.expressions.access_log_settings[_].destination_arn.references) > 0

has_throttle(r) if r.expressions.default_route_settings[_].throttling_rate_limit.constant_value > 0
