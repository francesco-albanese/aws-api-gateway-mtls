terraform {
  required_version = ">= 1.14.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.28.0"
    }
  }

  # Backend configuration provided via -backend-config=../../state.conf
  backend "s3" {}
}
