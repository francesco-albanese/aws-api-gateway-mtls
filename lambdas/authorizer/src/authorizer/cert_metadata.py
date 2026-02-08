"""DynamoDB operations for certificate metadata lookup."""

import boto3
from botocore.exceptions import ClientError

from authorizer.types import CertMetadata

_dynamodb_client = boto3.client("dynamodb")


def lookup_cert_metadata(serial_number: str, table_name: str) -> CertMetadata | None:
    """Lookup certificate metadata from DynamoDB by serial number."""
    try:
        response = _dynamodb_client.get_item(
            TableName=table_name,
            Key={"serialNumber": {"S": serial_number}},
        )
    except ClientError:
        return None

    item = response.get("Item")
    if not item:
        return None

    try:
        return {
            "serialNumber": item["serialNumber"]["S"],
            "client_id": item.get("client_id", {}).get("S", ""),
            "clientName": item["clientName"]["S"],
            "status": item["status"]["S"],
            "issuedAt": item["issuedAt"]["S"],
            "expiry": item["expiry"]["S"],
        }
    except (KeyError, TypeError):
        return None
