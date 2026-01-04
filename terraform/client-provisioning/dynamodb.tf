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
    Name = "mtls-clients-metadata"
  }
}

resource "aws_dynamodb_table_item" "client_metadata" {
  for_each = local.clients

  table_name = aws_dynamodb_table.mtls_clients_metadata.name
  hash_key   = aws_dynamodb_table.mtls_clients_metadata.hash_key

  item = jsonencode({
    serialNumber = { S = each.value.serialNumber }
    client_id    = { S = each.key }
    clientName   = { S = each.value.clientName }
    status       = { S = each.value.status }
    issuedAt     = { S = each.value.issuedAt }
    expiry       = { S = each.value.expiry }
    ttl          = { N = tostring(each.value.ttl) }
  })

  lifecycle {
    ignore_changes = [item]
  }
}
