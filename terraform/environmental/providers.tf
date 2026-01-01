provider "aws" {
  region = var.region

  # Conditional assume_role:
  # - Local dev (skip_provider_assume_role=false): assume terraform role in target account
  # - GitHub OIDC (skip_provider_assume_role=true): already authenticated, skip assume_role
  dynamic "assume_role" {
    for_each = !var.skip_provider_assume_role && var.account_id != "" ? [1] : []
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
