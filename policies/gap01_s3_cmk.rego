# policies/gap01_s3_cmk.rego
# METADATA
# title: GAP-01 — S3 uploads use a customer CMK
# description: "Every aws_s3_bucket must have SSE-KMS with a customer CMK, not SSE-S3."
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   gap: GAP-01
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and kms_master_key_id."
package compliance.gap01_s3_cmk

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_kms(bucket)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] %s: missing SSE-KMS (customer CMK). Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms.", [bucket])
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	def := r.expressions.rule[_].apply_server_side_encryption_by_default[_]
	def.sse_algorithm.constant_value == "aws:kms"
	count(def.kms_master_key_id.references) > 0
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
