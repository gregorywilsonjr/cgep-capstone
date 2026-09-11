# policies/gap03_s3_tls.rego
# METADATA
# title: GAP-03 — S3 denies non-TLS
# description: "Each aws_s3_bucket must have a bucket policy denying aws:SecureTransport=false."
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   gap: GAP-03
#   severity: high
#   remediation: "Add aws_s3_bucket_policy denying s3:* when aws:SecureTransport is false."
package compliance.gap03_s3_tls

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_tls_deny(bucket)
	msg := sprintf("[HIPAA 164.312(e)(1)] %s: no bucket policy denying non-TLS (aws:SecureTransport=false).", [bucket])
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_tls_deny(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	policy := r.expressions.policy.constant_value
	contains(policy, "aws:SecureTransport")
}

has_tls_deny(bucket_addr) if {
	some br in input.planned_values.root_module.resources
	br.address == bucket_addr
	bucket_name := br.values.bucket
	bucket_name != null
	some pr in input.planned_values.root_module.resources
	pr.type == "aws_s3_bucket_policy"
	pr.values.bucket == bucket_name
	contains(pr.values.policy, "aws:SecureTransport")
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
