"""DynamoDB client for certificate metadata operations."""

import logging
from typing import cast

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from mypy_boto3_dynamodb import DynamoDBClient as DynamoDBClientType
from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource
from mypy_boto3_dynamodb.type_defs import TableAttributeValueTypeDef

from ca_operations.lib.models import CertificateMetadata

logger = logging.getLogger(__name__)

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

        Only revokes if the item exists and is currently active.

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
                ConditionExpression="attribute_exists(serialNumber) AND #s = :active",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":status": "revoked", ":active": "active"},
            )
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "ConditionalCheckFailedException":
                logger.warning(
                    "Revoke condition failed for %s: item missing or not active",
                    serial_number,
                )
            else:
                logger.error("Failed to revoke cert %s: %s", serial_number, e)
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
            table.put_item(Item=cast(dict[str, TableAttributeValueTypeDef], dict(metadata)))
            return True
        except ClientError as e:
            logger.error("Failed to put cert metadata %s: %s", metadata.get("serialNumber"), e)
            return False

    def rotate_certificate(
        self,
        table_name: str,
        old_serial: str,
        new_metadata: CertificateMetadata,
    ) -> bool:
        """Atomically revoke old cert and insert new cert metadata.

        Uses DynamoDB transact_write_items to ensure both operations
        succeed or both fail.

        Args:
            table_name: DynamoDB table name
            old_serial: Serial number of certificate to revoke
            new_metadata: New certificate metadata to insert

        Returns:
            True if transaction succeeded, False otherwise
        """
        try:
            self.client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": table_name,
                            "Key": {"serialNumber": {"S": old_serial}},
                            "UpdateExpression": "SET #s = :status",
                            "ConditionExpression": "attribute_exists(serialNumber) AND #s = :active",
                            "ExpressionAttributeNames": {"#s": "status"},
                            "ExpressionAttributeValues": {
                                ":status": {"S": "revoked"},
                                ":active": {"S": "active"},
                            },
                        }
                    },
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                k: {"S": str(v)} if isinstance(v, str) else {"N": str(v)}
                                for k, v in new_metadata.items()
                            },
                        }
                    },
                ]
            )
            return True
        except ClientError as e:
            logger.error(
                "Transaction failed rotating %s -> %s: %s",
                old_serial,
                new_metadata.get("serialNumber"),
                e,
            )
            return False
