"""Tests for DynamoDB client module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from ca_operations.lib.dynamodb_client import CertificateMetadata, DynamoDBClient


class TestDynamoDBClient:
    """Tests for DynamoDBClient class."""

    @pytest.fixture
    def mock_boto3(self) -> MagicMock:
        """Mock boto3 for DynamoDB."""
        with patch("ca_operations.lib.dynamodb_client.boto3") as mock:
            yield mock

    def test_get_active_certificates_empty(self, mock_boto3: MagicMock) -> None:
        """Should return empty list when no active certs."""
        mock_table = MagicMock()
        mock_table.scan.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        result = client.get_active_certificates("test-table")

        assert result == []
        mock_table.scan.assert_called_once()

    def test_get_active_certificates_returns_metadata(self, mock_boto3: MagicMock) -> None:
        """Should return certificate metadata list."""
        mock_table = MagicMock()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "serialNumber": "AB:CD:EF:12",
                    "client_id": "client-001",
                    "clientName": "client-001",
                    "status": "active",
                    "issuedAt": "2025-01-01T00:00:00+00:00",
                    "expiry": "2026-01-01T00:00:00+00:00",
                    "notBefore": "2025-01-01T00:00:00+00:00",
                    "ttl": 1735689600,
                }
            ]
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        result = client.get_active_certificates("test-table")

        assert len(result) == 1
        assert result[0]["serialNumber"] == "AB:CD:EF:12"
        assert result[0]["client_id"] == "client-001"

    def test_get_active_certificates_handles_pagination(self, mock_boto3: MagicMock) -> None:
        """Should handle paginated results."""
        mock_table = MagicMock()
        mock_table.scan.side_effect = [
            {
                "Items": [
                    {
                        "serialNumber": "AA:BB",
                        "clientName": "c1",
                        "status": "active",
                        "issuedAt": "",
                        "expiry": "",
                        "notBefore": "",
                        "ttl": 0,
                    }
                ],
                "LastEvaluatedKey": {"serialNumber": "AA:BB"},
            },
            {
                "Items": [
                    {
                        "serialNumber": "CC:DD",
                        "clientName": "c2",
                        "status": "active",
                        "issuedAt": "",
                        "expiry": "",
                        "notBefore": "",
                        "ttl": 0,
                    }
                ],
            },
        ]
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        result = client.get_active_certificates("test-table")

        assert len(result) == 2
        assert mock_table.scan.call_count == 2

    def test_revoke_certificate_success(self, mock_boto3: MagicMock) -> None:
        """Should update certificate status to revoked."""
        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        result = client.revoke_certificate("test-table", "AB:CD:EF")

        assert result is True
        mock_table.update_item.assert_called_once()

    def test_put_certificate_metadata_success(self, mock_boto3: MagicMock) -> None:
        """Should insert metadata into DynamoDB."""
        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        metadata = CertificateMetadata(
            serialNumber="AB:CD",
            client_id="client-001",
            clientName="client-001",
            status="active",
            issuedAt="2025-01-01T00:00:00+00:00",
            expiry="2026-01-01T00:00:00+00:00",
            notBefore="2025-01-01T00:00:00+00:00",
            ttl=1735689600,
        )
        result = client.put_certificate_metadata("test-table", metadata)

        assert result is True
        mock_table.put_item.assert_called_once()

    def test_revoke_certificate_failure(self, mock_boto3: MagicMock) -> None:
        """Should return False on ClientError."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "test"}}, "UpdateItem"
        )
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        result = client.revoke_certificate("test-table", "AB:CD:EF")

        assert result is False

    def test_put_certificate_metadata_failure(self, mock_boto3: MagicMock) -> None:
        """Should return False on ClientError."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "test"}}, "PutItem"
        )
        mock_boto3.resource.return_value.Table.return_value = mock_table

        client = DynamoDBClient()
        metadata = CertificateMetadata(
            serialNumber="AB:CD",
            client_id="client-001",
            clientName="client-001",
            status="active",
            issuedAt="2025-01-01T00:00:00+00:00",
            expiry="2026-01-01T00:00:00+00:00",
            notBefore="2025-01-01T00:00:00+00:00",
            ttl=1735689600,
        )
        result = client.put_certificate_metadata("test-table", metadata)

        assert result is False
