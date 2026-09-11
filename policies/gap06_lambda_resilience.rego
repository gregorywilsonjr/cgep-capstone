# policies/gap06_lambda_resilience.rego
# METADATA
# title: GAP-06 — Lambda DLQ and X-Ray
# description: "aws_lambda_function must set dead_letter_config and Active tracing. Reserved concurrency is omitted: new accounts cannot reserve without dropping UnreservedConcurrentExecution below 10."
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(7)"]
#   gap: GAP-06
#   severity: medium
#   remediation: "Add dead_letter_config and tracing_config { mode = Active }. Request a concurrency quota increase before setting reserved_concurrent_executions."
package compliance.gap06_lambda_resilience

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not has_dlq(r)
	msg := sprintf("[HIPAA 164.308(a)(7)] aws_lambda_function.%s: missing dead_letter_config.", [r.name])
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not has_xray(r)
	msg := sprintf("[HIPAA 164.308(a)(7)] aws_lambda_function.%s: tracing_config.mode is not Active.", [r.name])
}

has_dlq(r) if count(r.expressions.dead_letter_config[_].target_arn.references) > 0

has_xray(r) if r.expressions.tracing_config[_].mode.constant_value == "Active"
