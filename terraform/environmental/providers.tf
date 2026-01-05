provider "aws" {
  region = var.region

  # Auth handled externally:
  # - Local dev: AWS profiles with assume_role in ~/.aws/config
  # - GitHub OIDC: configure-aws-credentials sets env vars

  default_tags {
    tags = {
      "franco:terraform_stack" = "aws-api-gateway-mtls"
      "franco:managed_by"      = "terraform"
      "franco:environment"     = var.account_name
    }
  }
}

# Cross-account provider for Route53 in shared-services account
provider "aws" {
  alias  = "route53"
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::${var.route53_account_id}:role/${var.route53_role_name}"
  }

  default_tags {
    tags = {
      "franco:terraform_stack" = "aws-api-gateway-mtls"
      "franco:managed_by"      = "terraform"
      "franco:environment"     = var.account_name
    }
  }
}
