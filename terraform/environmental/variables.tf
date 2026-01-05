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
  default     = "apigw-mtls"
}

variable "domain_name" {
  description = "Base domain name (e.g., example.com)"
  type        = string
}

variable "api_subdomain" {
  description = "Subdomain for API (e.g., api-sandbox, api-staging, api)"
  type        = string
  default     = "api"
}

variable "route53_account_id" {
  description = "AWS account ID hosting Route53 zone (shared-services)"
  type        = string
}

variable "route53_role_name" {
  description = "IAM role name for Route53 cross-account access"
  type        = string
  default     = "terraform"
}