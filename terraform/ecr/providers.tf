provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "franco:terraform_stack" = "aws-api-gateway-mtls-ecr"
      "franco:managed_by"      = "terraform"
      "franco:environment"     = var.account_name
    }
  }
}
