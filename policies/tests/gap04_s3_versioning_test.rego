# policies/tests/gap04_s3_versioning_test.rego
package compliance.gap04_s3_versioning_test

import rego.v1
import data.compliance.gap04_s3_versioning

good := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
	{
		"type": "aws_s3_bucket_versioning",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
		},
	},
]}}}

bad := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
]}}}

test_good if { count(gap04_s3_versioning.deny) == 0 with input as good }

test_bad if {
	some msg in gap04_s3_versioning.deny with input as bad
	contains(msg, "164.308(a)(7)")
}
