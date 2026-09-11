# policies/tests/gap02_ddb_cmk_test.rego
package compliance.gap02_ddb_cmk_test

import rego.v1
import data.compliance.gap02_ddb_cmk

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.intake.arn"]},
	}]},
}]}}}

bad := {"configuration": {"root_module": {"resources": [{
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {},
}]}}}

test_good if { count(gap02_ddb_cmk.deny) == 0 with input as good }

test_bad if {
	some msg in gap02_ddb_cmk.deny with input as bad
	contains(msg, "164.312(a)(2)(iv)")
}
