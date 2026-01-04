provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "franco:terraform_stack" = "aws-api-gateway-mtls-client-provisioning"
      "franco:managed_by"      = "terraform"
      "franco:environment"     = var.account_name
    }
  }
}
