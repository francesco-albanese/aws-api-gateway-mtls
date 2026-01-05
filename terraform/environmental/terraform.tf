terraform {
  required_version = ">= 1.14.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.18.0"
    }
  }

  # Backend configuration provided via -backend-config=../../state.conf
  # Key must be unique per environment - passed via -backend-config key=environmental/{env}/terraform.tfstate
  backend "s3" {
    # bucket, region, key, assume_role from -backend-config
  }
}

# Cross-account provider for Route53 operations (zone in shared-services)
provider "aws" {
  alias  = "route53"
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::${var.route53_account_id}:role/${var.route53_role_name}"
  }
}
