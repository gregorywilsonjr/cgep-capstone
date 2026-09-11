# policies/tests/gap05_lambda_vpc_test.rego
package compliance.gap05_lambda_vpc_test

import rego.v1
import data.compliance.gap05_lambda_vpc

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{"subnet_ids": {"references": ["aws_subnet.private"]}}]},
}]}}}

bad := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_good if { count(gap05_lambda_vpc.deny) == 0 with input as good }

test_bad if {
	some msg in gap05_lambda_vpc.deny with input as bad
	contains(msg, "164.312(e)(1)")
}
