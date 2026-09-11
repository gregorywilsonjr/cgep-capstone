# terraform/oidc-trust.tf
# Reuse the GitHub OIDC provider already in this account from Lab 4.3.
# A second aws_iam_openid_connect_provider for the same URL fails.

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  github_org      = "gregorywilsonjr"
  github_repo     = "cgep-capstone"
  github_owner_id = "76980815"
  github_repo_id  = "1365136271"
  classic_sub     = "repo:${local.github_org}/${local.github_repo}:*"
  immutable_sub   = "repo:${local.github_org}@${local.github_owner_id}/${local.github_repo}@${local.github_repo_id}:*"
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-capstone-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            local.classic_sub,
            local.immutable_sub,
          ]
        }
      }
    }]
  })
}

# Sandbox, 30-day project, apply-on-merge. Production would split plan vs apply
# roles and drop AdministratorAccess. Defended in WRITEUP.md.
resource "aws_iam_role_policy_attachment" "grc_gate_admin" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "grc_gate_role_arn" {
  value = aws_iam_role.grc_gate.arn
}

output "evidence_vault" {
  value = aws_s3_bucket.vault.id
}

output "kms_key_arn" {
  value = aws_kms_key.intake.arn
}
