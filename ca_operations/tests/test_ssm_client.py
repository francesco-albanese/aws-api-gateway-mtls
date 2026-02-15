"""Tests for SSM client module."""

from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from ca_operations.lib.ssm_client import SSMClient


class TestGetRootCA:
    """Tests for SSMClient.get_root_ca."""

    @pytest.fixture
    def mock_boto3(self) -> Generator[MagicMock]:
        with patch("ca_operations.lib.ssm_client.boto3") as mock:
            yield mock

    def test_returns_key_and_cert_bytes(self, mock_boto3: MagicMock) -> None:
        """Should return (key_pem, cert_pem) as bytes."""
        mock_client = mock_boto3.client.return_value
        key_val = "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----"
        cert_val = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
        mock_client.get_parameter.side_effect = [
            {"Parameter": {"Value": key_val}},
            {"Parameter": {"Value": cert_val}},
        ]

        client = SSMClient()
        key_pem, cert_pem = client.get_root_ca("apigw-mtls", "sandbox")

        assert isinstance(key_pem, bytes)
        assert isinstance(cert_pem, bytes)
        assert b"BEGIN RSA PRIVATE KEY" in key_pem
        assert b"BEGIN CERTIFICATE" in cert_pem

    def test_uses_correct_ssm_paths(self, mock_boto3: MagicMock) -> None:
        """Should fetch from /{project}/{account}/ca/root/ paths."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = [
            {"Parameter": {"Value": "key-data"}},
            {"Parameter": {"Value": "cert-data"}},
        ]

        client = SSMClient()
        client.get_root_ca("apigw-mtls", "sandbox")

        calls = mock_client.get_parameter.call_args_list
        assert calls[0][1]["Name"] == "/apigw-mtls/sandbox/ca/root/private-key"
        assert calls[0][1]["WithDecryption"] is True
        assert calls[1][1]["Name"] == "/apigw-mtls/sandbox/ca/root/certificate"
        assert calls[1][1]["WithDecryption"] is False

    def test_raises_value_error_on_parameter_not_found(self, mock_boto3: MagicMock) -> None:
        """Should raise ValueError with paths when ParameterNotFound."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": "not found"}},
            "GetParameter",
        )

        client = SSMClient()
        with pytest.raises(ValueError, match="Root CA not found in SSM"):
            client.get_root_ca("apigw-mtls", "sandbox")

    def test_reraises_non_parameter_not_found_errors(self, mock_boto3: MagicMock) -> None:
        """Should re-raise ClientError for non-ParameterNotFound codes."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no access"}},
            "GetParameter",
        )

        client = SSMClient()
        with pytest.raises(ClientError):
            client.get_root_ca("apigw-mtls", "sandbox")


class TestPutIntermediateCA:
    """Tests for SSMClient.put_intermediate_ca."""

    @pytest.fixture
    def mock_boto3(self) -> Generator[MagicMock]:
        with patch("ca_operations.lib.ssm_client.boto3") as mock:
            yield mock

    def test_writes_key_as_secure_string(self, mock_boto3: MagicMock) -> None:
        """Should put private key as SecureString with Overwrite."""
        mock_client = mock_boto3.client.return_value

        client = SSMClient()
        client.put_intermediate_ca("apigw-mtls", "sandbox", b"key-pem", b"cert-pem")

        calls = mock_client.put_parameter.call_args_list
        key_call = calls[0][1]
        assert key_call["Name"] == "/apigw-mtls/sandbox/ca/intermediate/private-key"
        assert key_call["Type"] == "SecureString"
        assert key_call["Overwrite"] is True
        assert key_call["Value"] == "key-pem"

    def test_writes_cert_as_string(self, mock_boto3: MagicMock) -> None:
        """Should put certificate as String with Overwrite."""
        mock_client = mock_boto3.client.return_value

        client = SSMClient()
        client.put_intermediate_ca("apigw-mtls", "sandbox", b"key-pem", b"cert-pem")

        calls = mock_client.put_parameter.call_args_list
        cert_call = calls[1][1]
        assert cert_call["Name"] == "/apigw-mtls/sandbox/ca/intermediate/certificate"
        assert cert_call["Type"] == "String"
        assert cert_call["Overwrite"] is True
        assert cert_call["Value"] == "cert-pem"

    def test_uses_correct_ssm_paths(self, mock_boto3: MagicMock) -> None:
        """Should write to /{project}/{account}/ca/intermediate/ paths."""
        mock_client = mock_boto3.client.return_value

        client = SSMClient()
        client.put_intermediate_ca("my-project", "production", b"k", b"c")

        calls = mock_client.put_parameter.call_args_list
        assert calls[0][1]["Name"] == "/my-project/production/ca/intermediate/private-key"
        assert calls[1][1]["Name"] == "/my-project/production/ca/intermediate/certificate"


class TestGetIntermediateCA:
    """Tests for SSMClient.get_intermediate_ca (existing method, regression)."""

    @pytest.fixture
    def mock_boto3(self) -> Generator[MagicMock]:
        with patch("ca_operations.lib.ssm_client.boto3") as mock:
            yield mock

    def test_returns_key_and_cert_bytes(self, mock_boto3: MagicMock) -> None:
        """Should return (key_pem, cert_pem) as bytes."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = [
            {"Parameter": {"Value": "key-data"}},
            {"Parameter": {"Value": "cert-data"}},
        ]

        client = SSMClient()
        key_pem, cert_pem = client.get_intermediate_ca("apigw-mtls", "sandbox")

        assert key_pem == b"key-data"
        assert cert_pem == b"cert-data"

    def test_raises_value_error_on_parameter_not_found(self, mock_boto3: MagicMock) -> None:
        """Should raise ValueError when ParameterNotFound."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": "not found"}},
            "GetParameter",
        )

        client = SSMClient()
        with pytest.raises(ValueError, match="Intermediate CA not found in SSM"):
            client.get_intermediate_ca("apigw-mtls", "sandbox")


class TestClientExists:
    """Tests for SSMClient.client_exists (existing method, regression)."""

    @pytest.fixture
    def mock_boto3(self) -> Generator[MagicMock]:
        with patch("ca_operations.lib.ssm_client.boto3") as mock:
            yield mock

    def test_returns_true_when_exists(self, mock_boto3: MagicMock) -> None:
        """Should return True when parameter exists."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.return_value = {"Parameter": {"Value": "cert"}}

        client = SSMClient()
        assert client.client_exists("apigw-mtls", "sandbox", "client-001") is True

    def test_returns_false_when_not_found(self, mock_boto3: MagicMock) -> None:
        """Should return False when ParameterNotFound."""
        mock_client = mock_boto3.client.return_value
        mock_client.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": "not found"}},
            "GetParameter",
        )

        client = SSMClient()
        assert client.client_exists("apigw-mtls", "sandbox", "client-001") is False
