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
