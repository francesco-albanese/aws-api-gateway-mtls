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
