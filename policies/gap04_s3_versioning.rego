# policies/gap04_s3_versioning.rego
# METADATA
# title: GAP-04 — S3 versioning enabled
# description: "Each aws_s3_bucket must have versioning Enabled (PHI overwrite recovery)."
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(7)"]
#   gap: GAP-04
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning { versioning_configuration { status = Enabled } }."
package compliance.gap04_s3_versioning

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_versioning(bucket)
	msg := sprintf("[HIPAA 164.308(a)(7)] %s: versioning is not Enabled.", [bucket])
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	# Object Lock vaults already require versioning; still check the companion resource.
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	status := r.expressions.versioning_configuration[_].status.constant_value
	status == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
