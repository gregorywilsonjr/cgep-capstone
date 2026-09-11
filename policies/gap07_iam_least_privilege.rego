# policies/gap07_iam_least_privilege.rego
# METADATA
# title: GAP-07 — no wildcard data-plane IAM on PHI stores
# description: "Inline IAM policies must not allow dynamodb:* or s3:*."
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(1)"]
#   gap: GAP-07
#   severity: high
#   remediation: "Replace dynamodb:* / s3:* with PutItem/GetItem and PutObject/GetObject on the specific ARNs."
package compliance.gap07_iam_least_privilege

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_iam_role_policy"
	policy := r.expressions.policy.constant_value
	wildcard_data_plane(policy)
	msg := sprintf("[HIPAA 164.312(a)(1)] aws_iam_role_policy.%s: policy allows dynamodb:* or s3:* (too broad for PHI).", [r.name])
}

wildcard_data_plane(policy) if contains(policy, "dynamodb:*")
wildcard_data_plane(policy) if contains(policy, "s3:*")

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	wildcard_data_plane(r.values.policy)
	msg := sprintf("[HIPAA 164.312(a)(1)] %s: policy allows dynamodb:* or s3:* (too broad for PHI).", [r.address])
}
