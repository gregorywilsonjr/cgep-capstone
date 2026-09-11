# policies/tests/gap01_s3_cmk_test.rego
package compliance.gap01_s3_cmk_test

import rego.v1
import data.compliance.gap01_s3_cmk

good := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
	{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": {"constant_value": "aws:kms"},
				"kms_master_key_id": {"references": ["aws_kms_key.intake.arn"]},
			}]}],
		},
	},
]}}}

bad := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
]}}}

aws_managed_kms := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads"},
	{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
		},
	},
]}}}

test_good if { count(gap01_s3_cmk.deny) == 0 with input as good }

test_bad if {
	some msg in gap01_s3_cmk.deny with input as bad
	contains(msg, "164.312(a)(2)(iv)")
}

test_aws_managed_kms if {
	some msg in gap01_s3_cmk.deny with input as aws_managed_kms
	contains(msg, "164.312(a)(2)(iv)")
}
