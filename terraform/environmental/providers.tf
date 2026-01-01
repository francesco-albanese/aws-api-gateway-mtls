# Detect current AWS account to conditionally assume_role
# Only assume_role when current account != target account
# Handles both local dev (management account) and GitHub OIDC (target account)
data "aws_caller_identity" "current" {}

provider "aws" {
  region = var.region

  # Conditional assume_role:
  # - Local dev: current = management, target = sandbox → assume_role
  # - GitHub OIDC: current = sandbox, target = sandbox → skip assume_role
  dynamic "assume_role" {
    for_each = data.aws_caller_identity.current.account_id != var.account_id ? [1] : []
    content {
      role_arn = "arn:aws:iam::${var.account_id}:role/terraform"
    }
  }

  default_tags {
    tags = {
      "franco:terraform_stack" = "aws-api-gateway-mtls"
      "franco:managed_by"      = "terraform"
      "franco:environment"     = var.account_name
    }
  }
}
