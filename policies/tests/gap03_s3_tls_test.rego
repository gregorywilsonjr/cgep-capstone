# policies/tests/gap03_s3_tls_test.rego
package compliance.gap03_s3_tls_test

import rego.v1
import data.compliance.gap03_s3_tls

good := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
	{
		"type": "aws_s3_bucket_policy",
		"name": "uploads_tls",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"policy": {"constant_value": "{\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}"},
		},
	},
]}}}

bad := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
]}}}

test_good if { count(gap03_s3_tls.deny) == 0 with input as good }

test_bad if {
	some msg in gap03_s3_tls.deny with input as bad
	contains(msg, "164.312(e)(1)")
}
