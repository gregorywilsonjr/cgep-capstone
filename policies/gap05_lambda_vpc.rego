# policies/gap05_lambda_vpc.rego
# METADATA
# title: GAP-05 — Lambda runs in the VPC
# description: "aws_lambda_function must set vpc_config with subnet_ids (the starter VPC)."
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   gap: GAP-05
#   severity: high
#   remediation: "Add vpc_config { subnet_ids = aws_subnet.private[*].id, security_group_ids = [...] }."
package compliance.gap05_lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not has_vpc(r)
	msg := sprintf("[HIPAA 164.312(e)(1)] aws_lambda_function.%s: missing vpc_config (Lambda is not in the VPC).", [r.name])
}

has_vpc(r) if count(r.expressions.vpc_config[_].subnet_ids.references) > 0
