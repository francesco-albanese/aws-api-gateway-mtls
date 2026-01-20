"""DynamoDB operations for certificate metadata lookup."""

import boto3
from botocore.exceptions import ClientError

from .types import CertMetadata


def get_dynamodb_client():
    """Get DynamoDB client."""
    return boto3.client("dynamodb")


def lookup_cert_metadata(serial_number: str, table_name: str) -> CertMetadata | None:
    """Lookup certificate metadata from DynamoDB by serial number.

    Args:
        serial_number: Certificate serial number (partition key)
        table_name: DynamoDB table name

    Returns:
        CertMetadata if found, None otherwise
    """
    dynamodb = get_dynamodb_client()
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={"serialNumber": {"S": serial_number}},
        )
    except ClientError:
        return None

    item = response.get("Item")
    if not item:
        return None

    return {
        "serialNumber": item["serialNumber"]["S"],
        "client_id": item["client_id"]["S"],
        "clientName": item["clientName"]["S"],
        "status": item["status"]["S"],
        "issuedAt": item["issuedAt"]["S"],
        "expiry": item["expiry"]["S"],
    }
