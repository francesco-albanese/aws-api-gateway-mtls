resource "aws_dynamodb_table" "mtls_clients_metadata" {
  name         = "mtls-clients-metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "serialNumber"

  attribute {
    name = "serialNumber"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "issuedAt"
    type = "S"
  }

  global_secondary_index {
    name            = "status-issuedAt-index"
    hash_key        = "status"
    range_key       = "issuedAt"
    projection_type = "ALL"
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
