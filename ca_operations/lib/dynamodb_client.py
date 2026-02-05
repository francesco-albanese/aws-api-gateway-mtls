"""DynamoDB client for certificate metadata operations."""

from typing import cast

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from mypy_boto3_dynamodb import DynamoDBClient as DynamoDBClientType
from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource
from mypy_boto3_dynamodb.type_defs import TableAttributeValueTypeDef

from ca_operations.lib.models import CertificateMetadata

GSI_STATUS_ISSUED_AT = "status-issuedAt-index"


def _parse_item_to_metadata(
    item: dict[str, TableAttributeValueTypeDef],
) -> CertificateMetadata:
    """Convert raw DynamoDB item to CertificateMetadata with explicit casts."""
    raw_ttl = item["ttl"]
    metadata = CertificateMetadata(
        serialNumber=str(item["serialNumber"]),
        clientName=str(item["clientName"]),
        status=str(item["status"]),
        issuedAt=str(item["issuedAt"]),
        expiry=str(item["expiry"]),
        notBefore=str(item["notBefore"]),
        ttl=int(cast(int, raw_ttl)),
    )
    client_id = item.get("client_id")
    if client_id is not None:
        metadata["client_id"] = str(client_id)
    return metadata


class DynamoDBClient:
    """DynamoDB client for certificate metadata operations."""

    def __init__(self, region: str = "eu-west-2") -> None:
        """Initialize DynamoDB client.

        Args:
            region: AWS region for DynamoDB client
        """
        self.client: DynamoDBClientType = boto3.client("dynamodb", region_name=region)
        self.resource: DynamoDBServiceResource = boto3.resource("dynamodb", region_name=region)

    def get_active_certificates(self, table_name: str) -> list[CertificateMetadata]:
        """Query all active certificates from DynamoDB using GSI.

        Args:
            table_name: DynamoDB table name

        Returns:
            List of certificate metadata for active certificates
        """
        table = self.resource.Table(table_name)
        active_certs: list[CertificateMetadata] = []

        response = table.query(
            IndexName=GSI_STATUS_ISSUED_AT,
            KeyConditionExpression=Key("status").eq("active"),
        )

        for item in response.get("Items", []):
            active_certs.append(_parse_item_to_metadata(item))

        # Handle pagination
        while "LastEvaluatedKey" in response:
            response = table.query(
                IndexName=GSI_STATUS_ISSUED_AT,
                KeyConditionExpression=Key("status").eq("active"),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            for item in response.get("Items", []):
                active_certs.append(_parse_item_to_metadata(item))

        return active_certs

    def revoke_certificate(self, table_name: str, serial_number: str) -> bool:
        """Mark certificate as revoked in DynamoDB.

        Args:
            table_name: DynamoDB table name
            serial_number: Certificate serial number (primary key)

        Returns:
            True if successful, False otherwise
        """
        table = self.resource.Table(table_name)

        try:
            table.update_item(
                Key={"serialNumber": serial_number},
                UpdateExpression="SET #s = :status",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":status": "revoked"},
            )
            return True
        except ClientError:
            return False

    def put_certificate_metadata(self, table_name: str, metadata: CertificateMetadata) -> bool:
        """Insert certificate metadata into DynamoDB.

        Args:
            table_name: DynamoDB table name
            metadata: Certificate metadata to insert

        Returns:
            True if successful, False otherwise
        """
        table = self.resource.Table(table_name)

        try:
            table.put_item(
                Item=cast(dict[str, TableAttributeValueTypeDef], dict(metadata))
            )
            return True
        except ClientError:
            return False
