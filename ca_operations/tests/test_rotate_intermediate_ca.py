"""Tests for rotate_intermediate_ca function."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.cert_utils import serialize_certificate, serialize_private_key
from ca_operations.lib.config import CAConfig
from ca_operations.scripts.rotate_intermediate_ca import rotate_intermediate_ca


@pytest.fixture
def mock_ssm_client() -> MagicMock:
    """Return mocked SSM client."""
    mock = MagicMock()
    mock.client = MagicMock()
    return mock


@pytest.fixture
def mock_dynamodb_client() -> MagicMock:
    """Return mocked DynamoDB client."""
    return MagicMock()


@pytest.fixture
def mock_s3_client() -> MagicMock:
    """Return mocked S3 client."""
    return MagicMock()


@pytest.fixture
def rotation_ca_config() -> CAConfig:
    """Return CA config for rotation tests."""
    return CAConfig(
        country="GB",
        state="London",
        locality="London",
        organization="Test Org",
        organizational_unit="Test Unit",
        root_validity_years=1,
        intermediate_validity_years=1,
        client_validity_days=30,
        key_size=2048,
    )


def _make_cert_metadata(client_id: str, serial_number: str) -> dict[str, str]:
    """Create mock certificate metadata."""
    now = datetime.now(tz=timezone.utc)
    return {
        "serialNumber": serial_number,
        "clientName": client_id,
        "client_id": client_id,
        "status": "active",
        "issuedAt": now.isoformat(),
        "expiry": now.isoformat(),
        "notBefore": now.isoformat(),
        "ttl": "1735689600",
    }


def test_happy_path(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test successful rotation with 1 active cert."""
    cert_metadata = _make_cert_metadata("test-client-001", "123ABC")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    client_cert_pem = serialize_certificate(client_cert)
    mock_ssm_client.client.get_parameter.return_value = {
        "Parameter": {"Value": client_cert_pem.decode("utf-8")}
    }

    mock_dynamodb_client.revoke_certificate.return_value = True
    mock_dynamodb_client.put_certificate_metadata.return_value = True
    mock_s3_client.upload_truststore.return_value = "v1"

    result = rotate_intermediate_ca(
        environment="sandbox",
        new_intermediate_key_pem=serialize_private_key(intermediate_key),
        new_intermediate_cert_pem=serialize_certificate(intermediate_cert),
        root_cert_pem=serialize_certificate(root_cert),
        dynamodb_table="test-table",
        s3_bucket="test-bucket",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        s3_client=mock_s3_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 1
    assert result.revoked_count == 1
    assert result.failed_count == 0
    assert result.truststore_version_id == "v1"
    assert len(result.reissued_serials) == 1
    assert len(result.failed_client_ids) == 0

    mock_ssm_client.client.put_parameter.assert_called_once()
    mock_s3_client.upload_truststore.assert_called_once()


def test_partial_failure_skips_truststore(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test partial failure with 2 certs, 1 SSM fetch fails, truststore NOT updated."""
    cert_metadata_1 = _make_cert_metadata("test-client-001", "123ABC")
    cert_metadata_2 = _make_cert_metadata("test-client-002", "456DEF")
    mock_dynamodb_client.get_active_certificates.return_value = [
        cert_metadata_1,
        cert_metadata_2,
    ]

    client_cert_pem = serialize_certificate(client_cert)

    def ssm_side_effect(*_args: object, **kwargs: object) -> dict[str, dict[str, str]]:
        name = kwargs.get("Name", "")
        if "test-client-001" in name:
            return {"Parameter": {"Value": client_cert_pem.decode("utf-8")}}
        raise RuntimeError("SSM fetch failed for test-client-002")

    mock_ssm_client.client.get_parameter.side_effect = ssm_side_effect

    mock_dynamodb_client.revoke_certificate.return_value = True
    mock_dynamodb_client.put_certificate_metadata.return_value = True

    result = rotate_intermediate_ca(
        environment="sandbox",
        new_intermediate_key_pem=serialize_private_key(intermediate_key),
        new_intermediate_cert_pem=serialize_certificate(intermediate_cert),
        root_cert_pem=serialize_certificate(root_cert),
        dynamodb_table="test-table",
        s3_bucket="test-bucket",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        s3_client=mock_s3_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 1
    assert result.failed_count == 1
    assert len(result.failed_client_ids) == 1
    assert "test-client-002" in result.failed_client_ids

    mock_s3_client.upload_truststore.assert_not_called()


def test_dry_run_no_aws_writes(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test dry_run mode with no AWS writes."""
    cert_metadata = _make_cert_metadata("test-client-001", "123ABC")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    client_cert_pem = serialize_certificate(client_cert)
    mock_ssm_client.client.get_parameter.return_value = {
        "Parameter": {"Value": client_cert_pem.decode("utf-8")}
    }

    result = rotate_intermediate_ca(
        environment="sandbox",
        new_intermediate_key_pem=serialize_private_key(intermediate_key),
        new_intermediate_cert_pem=serialize_certificate(intermediate_cert),
        root_cert_pem=serialize_certificate(root_cert),
        dynamodb_table="test-table",
        s3_bucket="test-bucket",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        s3_client=mock_s3_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=True,
    )

    assert result.reissued_count == 1
    assert result.revoked_count == 0
    assert result.failed_count == 0

    mock_dynamodb_client.revoke_certificate.assert_not_called()
    mock_ssm_client.client.put_parameter.assert_not_called()
    mock_s3_client.upload_truststore.assert_not_called()


def test_empty_active_certs_updates_truststore(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test no active certs, truststore still updated."""
    mock_dynamodb_client.get_active_certificates.return_value = []
    mock_s3_client.upload_truststore.return_value = "v2"

    result = rotate_intermediate_ca(
        environment="sandbox",
        new_intermediate_key_pem=serialize_private_key(intermediate_key),
        new_intermediate_cert_pem=serialize_certificate(intermediate_cert),
        root_cert_pem=serialize_certificate(root_cert),
        dynamodb_table="test-table",
        s3_bucket="test-bucket",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        s3_client=mock_s3_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 0
    assert result.failed_count == 0
    assert result.truststore_version_id == "v2"

    mock_s3_client.upload_truststore.assert_called_once()


def test_invalid_metadata_skipped(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test cert with missing serialNumber is skipped and added to failed list."""
    invalid_cert_metadata = {
        "serialNumber": "",
        "clientName": "test-client-001",
        "status": "active",
        "issuedAt": datetime.now(tz=timezone.utc).isoformat(),
    }
    mock_dynamodb_client.get_active_certificates.return_value = [invalid_cert_metadata]

    result = rotate_intermediate_ca(
        environment="sandbox",
        new_intermediate_key_pem=serialize_private_key(intermediate_key),
        new_intermediate_cert_pem=serialize_certificate(intermediate_cert),
        root_cert_pem=serialize_certificate(root_cert),
        dynamodb_table="test-table",
        s3_bucket="test-bucket",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        s3_client=mock_s3_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.failed_count == 1
    assert result.reissued_count == 0
    assert "test-client-001" in result.failed_client_ids

    mock_ssm_client.client.get_parameter.assert_not_called()
    mock_s3_client.upload_truststore.assert_not_called()
