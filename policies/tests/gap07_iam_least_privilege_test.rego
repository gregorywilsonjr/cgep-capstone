# policies/tests/gap07_iam_least_privilege_test.rego
package compliance.gap07_iam_least_privilege_test

import rego.v1
import data.compliance.gap07_iam_least_privilege

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_iam_role_policy",
	"name": "lambda_inline",
	"expressions": {"policy": {"constant_value": "{\"Action\":[\"dynamodb:PutItem\"]}" }},
}]}}}

bad := {"configuration": {"root_module": {"resources": [{
	"type": "aws_iam_role_policy",
	"name": "lambda_inline",
	"expressions": {"policy": {"constant_value": "{\"Action\":\"dynamodb:*\"}" }},
}]}}}

test_good if { count(gap07_iam_least_privilege.deny) == 0 with input as good }

test_bad if {
	some msg in gap07_iam_least_privilege.deny with input as bad
	contains(msg, "164.312(a)(1)")
}
