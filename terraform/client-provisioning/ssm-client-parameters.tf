resource "aws_ssm_parameter" "client_private_key" {
  for_each = local.clients

  name  = "/${var.project_name}/${var.account_name}/clients/${each.key}/private-key"
  type  = "SecureString"
  value = file("${local.clients_base_path}/${each.key}/client.key")

  tags = {
    Name      = "${each.key}-private-key"
    client_id = each.key
  }
}

resource "aws_ssm_parameter" "client_certificate" {
  for_each = local.clients

  name  = "/${var.project_name}/${var.account_name}/clients/${each.key}/certificate"
  type  = "String"
  value = file("${local.clients_base_path}/${each.key}/client.pem")

  tags = {
    Name      = "${each.key}-certificate"
    client_id = each.key
  }
}
