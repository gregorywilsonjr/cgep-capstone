# terraform/kms.tf
# Layer 1: customer CMK with rotation. PHI (uploads + DynamoDB), CloudTrail,
# and the evidence vault all use this key.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "intake" {
  description             = "Acme Health intake PHI and evidence CMK"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "intake" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.intake.key_id
}
