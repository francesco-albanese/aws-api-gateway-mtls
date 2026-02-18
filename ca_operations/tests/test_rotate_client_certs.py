"""Tests for rotate_client_certs function."""

import logging
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.cert_utils import serialize_certificate, serialize_private_key
from ca_operations.lib.config import CAConfig
from ca_operations.scripts.rotate_client_certs import main, rotate_client_certs


@pytest.fixture
def mock_ssm_client() -> MagicMock:
    """Return mocked SSM client."""
    return MagicMock()


@pytest.fixture
def mock_dynamodb_client() -> MagicMock:
    """Return mocked DynamoDB client."""
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
    now = datetime.now(tz=UTC)
    return {
        "serialNumber": serial_number,
        "clientName": client_id,
        "client_id": client_id,
        "status": "active",
        "issuedAt": now.isoformat(),
        "expiry": now.isoformat(),
        "ttl": "1735689600",
    }


def test_happy_path(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test successful rotation with --all, 1 active client."""
    cert_metadata = _make_cert_metadata("test-client-001", "123456789")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )
    mock_dynamodb_client.rotate_certificate.return_value = True

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 1
    assert result.failed_count == 0
    assert len(result.reissued_serials) == 1
    assert len(result.failed_client_ids) == 0

    mock_dynamodb_client.rotate_certificate.assert_called_once()
    mock_ssm_client.put_client_certificate.assert_called_once()

    # Verify artifacts written
    client_dir = temp_output_dir / "test-client-001"
    assert (client_dir / "client.pem").exists()
    assert (client_dir / "metadata.json").exists()


def test_partial_failure(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test 2 clients, 1 SSM fetch fails."""
    cert_metadata_1 = _make_cert_metadata("test-client-001", "123456789")
    cert_metadata_2 = _make_cert_metadata("test-client-002", "987654321")
    mock_dynamodb_client.get_active_certificates.return_value = [
        cert_metadata_1,
        cert_metadata_2,
    ]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )

    client_key_pem = serialize_private_key(client_key)
    client_cert_pem = serialize_certificate(client_cert)

    def ssm_get_client_side_effect(_project: str, _env: str, cid: str) -> tuple[bytes, bytes]:
        if cid == "test-client-001":
            return client_key_pem, client_cert_pem
        raise RuntimeError("SSM fetch failed for test-client-002")

    mock_ssm_client.get_client_certificate.side_effect = ssm_get_client_side_effect
    mock_dynamodb_client.rotate_certificate.return_value = True

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 1
    assert result.failed_count == 1
    assert "test-client-002" in result.failed_client_ids


def test_dry_run_no_aws_writes(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test dry_run mode makes no AWS writes."""
    cert_metadata = _make_cert_metadata("test-client-001", "123456789")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=True,
    )

    assert result.reissued_count == 1
    assert result.failed_count == 0

    mock_dynamodb_client.rotate_certificate.assert_not_called()
    mock_ssm_client.put_client_certificate.assert_not_called()


def test_empty_active_certs(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test no active certs exits cleanly."""
    mock_dynamodb_client.get_active_certificates.return_value = []

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 0
    assert result.failed_count == 0
    assert result.reissued_serials == []
    assert result.failed_client_ids == []

    mock_ssm_client.get_client_certificate.assert_not_called()


def test_client_id_filter(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test --client-id filters to specific client only."""
    cert_metadata_1 = _make_cert_metadata("test-client-001", "123456789")
    cert_metadata_2 = _make_cert_metadata("test-client-002", "987654321")
    mock_dynamodb_client.get_active_certificates.return_value = [
        cert_metadata_1,
        cert_metadata_2,
    ]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )
    mock_dynamodb_client.rotate_certificate.return_value = True

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        client_id_filter="test-client-001",
        dry_run=False,
    )

    assert result.reissued_count == 1
    assert result.failed_count == 0
    # Only fetched client-001, not client-002
    mock_ssm_client.get_client_certificate.assert_called_once()
    call_args = mock_ssm_client.get_client_certificate.call_args
    assert call_args[0][2] == "test-client-001"


def test_dynamodb_transaction_failure(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test rotate_certificate returns False adds to failed list."""
    cert_metadata = _make_cert_metadata("test-client-001", "123456789")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )
    mock_dynamodb_client.rotate_certificate.return_value = False

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.failed_count == 1
    assert "test-client-001" in result.failed_client_ids
    assert result.reissued_count == 0

    # SSM should NOT be updated since DynamoDB transaction failed
    mock_ssm_client.put_client_certificate.assert_not_called()


def test_ssm_write_failure_triggers_rollback(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test SSM put_client_certificate failure triggers DynamoDB rollback."""
    cert_metadata = _make_cert_metadata("test-client-001", "123456789")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )
    mock_dynamodb_client.rotate_certificate.return_value = True
    mock_ssm_client.put_client_certificate.side_effect = RuntimeError("SSM write failed")
    mock_dynamodb_client.rollback_rotate_certificate.return_value = True

    result = rotate_client_certs(
        environment="sandbox",
        dynamodb_table="test-table",
        ssm_client=mock_ssm_client,
        dynamodb_client=mock_dynamodb_client,
        config=rotation_ca_config,
        output_dir=temp_output_dir,
        dry_run=False,
    )

    assert result.reissued_count == 0
    assert result.failed_count == 1
    assert "test-client-001" in result.failed_client_ids

    # Verify rollback was called with correct args
    mock_dynamodb_client.rollback_rotate_certificate.assert_called_once()
    call_args = mock_dynamodb_client.rollback_rotate_certificate.call_args[0]
    assert call_args[0] == "test-table"
    assert call_args[1] == "123456789"
    # new_serial is dynamic, just verify it's a string
    assert isinstance(call_args[2], str)


def test_ssm_write_failure_rollback_fails(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
    client_key: RSAPrivateKey,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test SSM failure + rollback failure emits CRITICAL log."""
    cert_metadata = _make_cert_metadata("test-client-001", "123456789")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    mock_ssm_client.get_intermediate_ca.return_value = (
        serialize_private_key(intermediate_key),
        serialize_certificate(intermediate_cert),
    )
    mock_ssm_client.get_client_certificate.return_value = (
        serialize_private_key(client_key),
        serialize_certificate(client_cert),
    )
    mock_dynamodb_client.rotate_certificate.return_value = True
    mock_ssm_client.put_client_certificate.side_effect = RuntimeError("SSM write failed")
    mock_dynamodb_client.rollback_rotate_certificate.return_value = False

    ca_logger = logging.getLogger("ca_operations")
    ca_logger.propagate = True
    try:
        with caplog.at_level(logging.CRITICAL, logger="ca_operations"):
            result = rotate_client_certs(
                environment="sandbox",
                dynamodb_table="test-table",
                ssm_client=mock_ssm_client,
                dynamodb_client=mock_dynamodb_client,
                config=rotation_ca_config,
                output_dir=temp_output_dir,
                dry_run=False,
            )
    finally:
        ca_logger.propagate = False

    assert result.failed_count == 1
    assert "test-client-001" in result.failed_client_ids

    # Verify CRITICAL rollback failure log was emitted
    critical_messages = [r.message for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("ROLLBACK FAILED" in msg and "test-client-001" in msg for msg in critical_messages)


def test_main_missing_args_returns_error() -> None:
    """Test main() exits with error when neither --client-id nor --all provided."""
    with (
        patch(
            "sys.argv",
            [
                "rotate_client_certs",
                "--environment",
                "sandbox",
            ],
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 2


def test_main_ssm_failure_returns_1() -> None:
    """Test main() exits with 1 when SSM fetch fails."""
    with (
        patch(
            "sys.argv",
            [
                "rotate_client_certs",
                "--environment",
                "sandbox",
                "--all",
            ],
        ),
        patch("ca_operations.scripts.rotate_client_certs.SSMClient") as mock_ssm_cls,
        patch("ca_operations.scripts.rotate_client_certs.DynamoDBClient"),
    ):
        mock_ssm_cls.return_value.get_intermediate_ca.side_effect = ValueError(
            "Intermediate CA not found"
        )
        # rotate_client_certs calls get_intermediate_ca internally
        exit_code = main()

    assert exit_code == 1
