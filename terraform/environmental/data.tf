# Data sources to read certificate infrastructure created by certificate-bootstrap stack

data "aws_s3_bucket" "mtls_truststore" {
  bucket = "${var.account_name}-mtls-truststore-${var.account_id}"
}

data "aws_ssm_parameter" "root_ca_private_key" {
  name = "/${var.project_name}/${var.account_name}/ca/root/private-key"
}

data "aws_ssm_parameter" "root_ca_certificate" {
  name = "/${var.project_name}/${var.account_name}/ca/root/certificate"
}

data "aws_ssm_parameter" "intermediate_ca_private_key" {
  name = "/${var.project_name}/${var.account_name}/ca/intermediate/private-key"
}

data "aws_ssm_parameter" "intermediate_ca_certificate" {
  name = "/${var.project_name}/${var.account_name}/ca/intermediate/certificate"
}

# ECR data sources for Lambda container images

data "aws_ecr_repository" "health_lambda" {
  name = local.ecr_repo_health
}

data "aws_ecr_image" "health_lambda" {
  repository_name = data.aws_ecr_repository.health_lambda.name
  image_tag       = var.health_lambda_image_tag
}

data "aws_ecr_repository" "authorizer_lambda" {
  name = local.ecr_repo_authorizer
}

data "aws_ecr_image" "authorizer_lambda" {
  repository_name = data.aws_ecr_repository.authorizer_lambda.name
  image_tag       = var.authorizer_lambda_image_tag
}
