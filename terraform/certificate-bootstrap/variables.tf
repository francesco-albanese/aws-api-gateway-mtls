variable "region" {
  type        = string
  description = "AWS region"
  default     = "eu-west-2"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "account_name" {
  type        = string
  description = "Account name (environment)"
}

variable "project_name" {
  type        = string
  description = "Project name for resource naming"
  default     = "aws-api-gateway-mtls"
}
