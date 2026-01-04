resource "aws_dynamodb_table" "mtls_clients_metadata" {
  name         = "mtls-clients-metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "serialNumber"

  attribute {
    name = "serialNumber"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name        = "mtls-clients-metadata"
    Project     = var.project_name
    Environment = var.account_name
  }
}
