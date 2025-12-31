# SSM Parameter Store resources for CA certificates and keys
# Stores Root CA and Intermediate CA private keys (SecureString) and certificates (String)

locals {
  ca_output_base = "${path.root}/../../ca_operations/output/${var.account_name}"
}

# Root CA Private Key (SecureString with AWS-managed KMS)
resource "aws_ssm_parameter" "root_ca_private_key" {
  name        = "/${var.project_name}/${var.account_name}/ca/root/private-key"
  description = "Root CA private key (RSA 4096)"
  type        = "SecureString"
  value       = file("${local.ca_output_base}/root-ca/RootCA.key")

  tags = {
    CA   = "root"
    Type = "private-key"
  }
}

# Root CA Certificate (String, not sensitive)
resource "aws_ssm_parameter" "root_ca_certificate" {
  name        = "/${var.project_name}/${var.account_name}/ca/root/certificate"
  description = "Root CA self-signed certificate (10yr validity)"
  type        = "String"
  value       = file("${local.ca_output_base}/root-ca/RootCA.pem")

  tags = {
    CA   = "root"
    Type = "certificate"
  }
}

# Intermediate CA Private Key (SecureString with AWS-managed KMS)
resource "aws_ssm_parameter" "intermediate_ca_private_key" {
  name        = "/${var.project_name}/${var.account_name}/ca/intermediate/private-key"
  description = "Intermediate CA private key (RSA 4096)"
  type        = "SecureString"
  value       = file("${local.ca_output_base}/intermediate-ca/IntermediateCA.key")

  tags = {
    CA   = "intermediate"
    Type = "private-key"
  }
}

# Intermediate CA Certificate (String)
resource "aws_ssm_parameter" "intermediate_ca_certificate" {
  name        = "/${var.project_name}/${var.account_name}/ca/intermediate/certificate"
  description = "Intermediate CA certificate signed by Root CA (5yr validity)"
  type        = "String"
  value       = file("${local.ca_output_base}/intermediate-ca/IntermediateCA.pem")

  tags = {
    CA   = "intermediate"
    Type = "certificate"
  }
}
