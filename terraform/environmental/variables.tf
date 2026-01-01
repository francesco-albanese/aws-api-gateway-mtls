variable "region" {
  description = "AWS region for infrastructure"
  type        = string
  default     = "eu-west-2"
}

variable "account_id" {
  description = "AWS account ID for this environmental account"
  type        = string
}

variable "account_name" {
  description = "The name of the account (sandbox/staging/uat/production)"
  type        = string
}

variable "project_name" {
  description = "Project name for parameter store namespacing"
  type        = string
  default     = "aws-api-gateway-mtls"
}

variable "skip_provider_assume_role" {
  description = "Skip provider assume_role (set to true when using GitHub OIDC)"
  type        = bool
  default     = false
}