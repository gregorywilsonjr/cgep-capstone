# policies/tests/gap06_lambda_resilience_test.rego
package compliance.gap06_lambda_resilience_test

import rego.v1
import data.compliance.gap06_lambda_resilience

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {
		"dead_letter_config": [{"target_arn": {"references": ["aws_sqs_queue.lambda_dlq.arn"]}}],
		"tracing_config": [{"mode": {"constant_value": "Active"}}],
	},
}]}}}

bad := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_good if { count(gap06_lambda_resilience.deny) == 0 with input as good }

test_bad if {
	count(gap06_lambda_resilience.deny) == 2 with input as bad
}
