data "aws_dynamodb_table" "mtls_clients_metadata" {
  name = "mtls-clients-metadata"
}

resource "aws_dynamodb_table_item" "client_metadata" {
  for_each = local.clients

  table_name = data.aws_dynamodb_table.mtls_clients_metadata.name
  hash_key   = data.aws_dynamodb_table.mtls_clients_metadata.hash_key

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
