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