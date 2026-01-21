"""DynamoDB client for certificate metadata operations."""

from typing import Any, TypedDict

import boto3
from botocore.exceptions import ClientError


class CertificateMetadata(TypedDict):
    """Certificate metadata from DynamoDB."""

    serialNumber: str
    client_id: str
    clientName: str
    status: str
    issuedAt: str
    expiry: str
    notBefore: str
    ttl: int


class DynamoDBClient:
    """DynamoDB client for certificate metadata operations."""

    def __init__(self, region: str = "eu-west-2") -> None:
        """Initialize DynamoDB client.

        Args:
            region: AWS region for DynamoDB client
        """
        self.client: Any = boto3.client("dynamodb", region_name=region)
        self.resource: Any = boto3.resource("dynamodb", region_name=region)

    def get_active_certificates(self, table_name: str) -> list[CertificateMetadata]:
        """Query all active certificates from DynamoDB.

        Args:
            table_name: DynamoDB table name

        Returns:
            List of certificate metadata for active certificates
        """
        table = self.resource.Table(table_name)
        active_certs: list[CertificateMetadata] = []

        # Scan for active certificates (small table, scan is fine)
        response = table.scan(
            FilterExpression="status = :status",
            ExpressionAttributeValues={":status": "active"},
        )

        for item in response.get("Items", []):
            active_certs.append(
                CertificateMetadata(
                    serialNumber=item["serialNumber"],
                    client_id=item.get("client_id", ""),
                    clientName=item["clientName"],
                    status=item["status"],
                    issuedAt=item["issuedAt"],
                    expiry=item["expiry"],
                    notBefore=item["notBefore"],
                    ttl=int(item["ttl"]),
                )
            )

        # Handle pagination
        while "LastEvaluatedKey" in response:
            response = table.scan(
                FilterExpression="status = :status",
                ExpressionAttributeValues={":status": "active"},
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            for item in response.get("Items", []):
                active_certs.append(
                    CertificateMetadata(
                        serialNumber=item["serialNumber"],
                        client_id=item.get("client_id", ""),
                        clientName=item["clientName"],
                        status=item["status"],
                        issuedAt=item["issuedAt"],
                        expiry=item["expiry"],
                        notBefore=item["notBefore"],
                        ttl=int(item["ttl"]),
                    )
                )

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
            table.put_item(Item=dict(metadata))
            return True
        except ClientError:
            return False
