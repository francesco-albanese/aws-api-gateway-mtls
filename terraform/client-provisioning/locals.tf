locals {
  clients_base_path = "${path.root}/../../ca_operations/output/${var.account_name}/clients"

  client_metadata_files = fileset(local.clients_base_path, "*/metadata.json")

  clients = {
    for f in local.client_metadata_files :
    dirname(f) => jsondecode(file("${local.clients_base_path}/${f}"))
  }
}
