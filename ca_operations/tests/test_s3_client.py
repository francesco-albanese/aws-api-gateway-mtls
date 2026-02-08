"""Tests for S3 client module."""

from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from ca_operations.lib.s3_client import S3Client


class TestS3Client:
    """Tests for S3Client class."""

    @pytest.fixture
    def mock_boto3(self) -> Generator[MagicMock]:
        """Mock boto3 for S3."""
        with patch("ca_operations.lib.s3_client.boto3") as mock:
            yield mock

    def test_upload_truststore_returns_version_id(self, mock_boto3: MagicMock) -> None:
        """Should return version ID from upload response."""
        mock_s3 = MagicMock()
        mock_s3.put_object.return_value = {"VersionId": "abc123"}
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        result = client.upload_truststore("test-bucket", b"pem content")

        assert result == "abc123"
        mock_s3.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="truststore.pem",
            Body=b"pem content",
            ContentType="application/x-pem-file",
        )

    def test_upload_truststore_no_versioning(self, mock_boto3: MagicMock) -> None:
        """Should return empty string when versioning disabled."""
        mock_s3 = MagicMock()
        mock_s3.put_object.return_value = {}
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        result = client.upload_truststore("test-bucket", b"pem content")

        assert result == ""

    def test_upload_truststore_custom_key(self, mock_boto3: MagicMock) -> None:
        """Should use custom key when provided."""
        mock_s3 = MagicMock()
        mock_s3.put_object.return_value = {}
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        client.upload_truststore("test-bucket", b"pem content", key="custom.pem")

        mock_s3.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="custom.pem",
            Body=b"pem content",
            ContentType="application/x-pem-file",
        )

    def test_get_truststore_returns_content(self, mock_boto3: MagicMock) -> None:
        """Should return truststore content as bytes."""
        mock_s3 = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = b"pem content"
        mock_s3.get_object.return_value = {"Body": mock_body}
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        result = client.get_truststore("test-bucket")

        assert result == b"pem content"
        mock_s3.get_object.assert_called_once_with(Bucket="test-bucket", Key="truststore.pem")

    def test_upload_truststore_failure(self, mock_boto3: MagicMock) -> None:
        """Should raise ClientError on upload failure."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "PutObject"
        )
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        with pytest.raises(ClientError):
            client.upload_truststore("test-bucket", b"pem content")

    def test_get_truststore_failure(self, mock_boto3: MagicMock) -> None:
        """Should raise ClientError on get failure."""
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Key not found"}}, "GetObject"
        )
        mock_boto3.client.return_value = mock_s3

        client = S3Client()
        with pytest.raises(ClientError):
            client.get_truststore("test-bucket")
