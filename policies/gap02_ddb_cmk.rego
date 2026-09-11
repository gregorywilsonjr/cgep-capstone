# policies/gap02_ddb_cmk.rego
# METADATA
# title: GAP-02 — DynamoDB uses a customer CMK
# description: "aws_dynamodb_table must enable server_side_encryption with kms_key_arn."
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   gap: GAP-02
#   severity: high
#   remediation: "Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<name>.arn }."
package compliance.gap02_ddb_cmk

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	not ddb_has_cmk(r)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] aws_dynamodb_table.%s: table is not encrypted with a customer CMK.", [r.name])
}

ddb_has_cmk(r) if {
	r.expressions.server_side_encryption[_].enabled.constant_value == true
	count(r.expressions.server_side_encryption[_].kms_key_arn.references) > 0
}
