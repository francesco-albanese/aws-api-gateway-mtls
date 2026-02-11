"""Tests for rotate_intermediate_ca function."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.cert_utils import serialize_certificate, serialize_private_key
from ca_operations.lib.config import CAConfig
from ca_operations.scripts.rotate_intermediate_ca import main, rotate_intermediate_ca


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
    now = datetime.now(tz=UTC)
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
    root_key: RSAPrivateKey,
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

    mock_dynamodb_client.rotate_certificate.return_value = True
    mock_s3_client.upload_truststore.return_value = "v1"

    result = rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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

    mock_ssm_client.put_intermediate_ca.assert_called_once()
    mock_dynamodb_client.rotate_certificate.assert_called_once()
    mock_ssm_client.client.put_parameter.assert_called_once()
    mock_s3_client.upload_truststore.assert_called_once()


def test_partial_failure_skips_truststore(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
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
        name = str(kwargs.get("Name", ""))
        if "test-client-001" in name:
            return {"Parameter": {"Value": client_cert_pem.decode("utf-8")}}
        raise RuntimeError("SSM fetch failed for test-client-002")

    mock_ssm_client.client.get_parameter.side_effect = ssm_side_effect

    mock_dynamodb_client.rotate_certificate.return_value = True

    result = rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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
    root_key: RSAPrivateKey,
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
        root_key_pem=serialize_private_key(root_key),
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

    # No AWS writes in dry_run
    mock_ssm_client.put_intermediate_ca.assert_not_called()
    mock_dynamodb_client.rotate_certificate.assert_not_called()
    mock_ssm_client.client.put_parameter.assert_not_called()
    mock_s3_client.upload_truststore.assert_not_called()


def test_empty_active_certs_updates_truststore(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test no active certs, truststore still updated."""
    mock_dynamodb_client.get_active_certificates.return_value = []
    mock_s3_client.upload_truststore.return_value = "v2"

    result = rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test cert with missing serialNumber is skipped and added to failed list."""
    invalid_cert_metadata = {
        "serialNumber": "",
        "clientName": "test-client-001",
        "status": "active",
        "issuedAt": datetime.now(tz=UTC).isoformat(),
    }
    mock_dynamodb_client.get_active_certificates.return_value = [invalid_cert_metadata]

    result = rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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


def test_rotate_certificate_failure_adds_to_failed(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    client_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Test rotate_certificate failure adds to failed, skips truststore."""
    cert_metadata = _make_cert_metadata("test-client-001", "123ABC")
    mock_dynamodb_client.get_active_certificates.return_value = [cert_metadata]

    client_cert_pem = serialize_certificate(client_cert)
    mock_ssm_client.client.get_parameter.return_value = {
        "Parameter": {"Value": client_cert_pem.decode("utf-8")}
    }

    mock_dynamodb_client.rotate_certificate.return_value = False

    result = rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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
    assert "test-client-001" in result.failed_client_ids
    assert result.reissued_count == 0
    mock_s3_client.upload_truststore.assert_not_called()


def test_intermediate_ca_stored_in_ssm(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Non-dry-run stores new intermediate CA in SSM via put_intermediate_ca."""
    mock_dynamodb_client.get_active_certificates.return_value = []
    mock_s3_client.upload_truststore.return_value = "v1"

    rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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

    mock_ssm_client.put_intermediate_ca.assert_called_once()
    call_args = mock_ssm_client.put_intermediate_ca.call_args
    assert call_args[0][0] == "apigw-mtls"
    assert call_args[0][1] == "sandbox"
    assert b"BEGIN" in call_args[0][2]  # key_pem
    assert b"BEGIN CERTIFICATE" in call_args[0][3]  # cert_pem


def test_dry_run_skips_ssm_intermediate_write(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Dry run does NOT call put_intermediate_ca."""
    mock_dynamodb_client.get_active_certificates.return_value = []

    rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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

    mock_ssm_client.put_intermediate_ca.assert_not_called()


def test_intermediate_artifacts_written(
    mock_ssm_client: MagicMock,
    mock_dynamodb_client: MagicMock,
    mock_s3_client: MagicMock,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    rotation_ca_config: CAConfig,
    temp_output_dir: Path,
) -> None:
    """Intermediate CA artifacts written to output_dir/intermediate-ca/."""
    mock_dynamodb_client.get_active_certificates.return_value = []
    mock_s3_client.upload_truststore.return_value = "v1"

    rotate_intermediate_ca(
        environment="sandbox",
        root_key_pem=serialize_private_key(root_key),
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

    intermediate_dir = temp_output_dir / "intermediate-ca"
    assert (intermediate_dir / "IntermediateCA.key").exists()
    assert (intermediate_dir / "IntermediateCA.pem").exists()
    assert (intermediate_dir / "IntermediateCA.csr").exists()
    assert (intermediate_dir / "metadata.json").exists()

    assert b"BEGIN" in (intermediate_dir / "IntermediateCA.key").read_bytes()
    assert b"BEGIN CERTIFICATE" in (intermediate_dir / "IntermediateCA.pem").read_bytes()


def test_main_ssm_failure_returns_1() -> None:
    """Test main() exits with 1 when SSM fetch fails."""
    with (
        patch(
            "sys.argv",
            [
                "rotate_intermediate_ca",
                "--environment",
                "sandbox",
                "--s3-bucket",
                "test-bucket",
            ],
        ),
        patch("ca_operations.scripts.rotate_intermediate_ca.SSMClient") as mock_ssm_cls,
        patch("ca_operations.scripts.rotate_intermediate_ca.DynamoDBClient"),
        patch("ca_operations.scripts.rotate_intermediate_ca.S3Client"),
    ):
        mock_ssm_cls.return_value.get_root_ca.side_effect = ValueError("Root CA not found in SSM")
        exit_code = main()

    assert exit_code == 1


def test_main_dry_run_propagated(
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    temp_output_dir: Path,
) -> None:
    """Test main() propagates --dry-run flag to rotate_intermediate_ca."""
    root_key_pem = serialize_private_key(root_key)
    root_cert_pem = serialize_certificate(root_cert)

    with (
        patch(
            "sys.argv",
            [
                "rotate_intermediate_ca",
                "--environment",
                "sandbox",
                "--s3-bucket",
                "test-bucket",
                "--output-dir",
                str(temp_output_dir / "out"),
                "--dry-run",
            ],
        ),
        patch("ca_operations.scripts.rotate_intermediate_ca.rotate_intermediate_ca") as mock_rotate,
        patch("ca_operations.scripts.rotate_intermediate_ca.SSMClient") as mock_ssm_cls,
        patch("ca_operations.scripts.rotate_intermediate_ca.DynamoDBClient"),
        patch("ca_operations.scripts.rotate_intermediate_ca.S3Client"),
    ):
        mock_ssm_cls.return_value.get_root_ca.return_value = (root_key_pem, root_cert_pem)

        from ca_operations.lib.models import RotationResult

        mock_rotate.return_value = RotationResult(
            reissued_count=0,
            revoked_count=0,
            failed_count=0,
            new_intermediate_serial="ABC",
            truststore_version_id="",
            reissued_serials=[],
            failed_client_ids=[],
        )
        exit_code = main()

    assert exit_code == 0
    mock_rotate.assert_called_once()
    call_kwargs = mock_rotate.call_args[1]
    assert call_kwargs["dry_run"] is True
    assert call_kwargs["root_key_pem"] == root_key_pem
    assert call_kwargs["root_cert_pem"] == root_cert_pem


def test_main_project_name_propagated(
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    temp_output_dir: Path,
) -> None:
    """Test main() passes --project-name to SSM client."""
    root_key_pem = serialize_private_key(root_key)
    root_cert_pem = serialize_certificate(root_cert)

    with (
        patch(
            "sys.argv",
            [
                "rotate_intermediate_ca",
                "--environment",
                "sandbox",
                "--project-name",
                "custom-project",
                "--s3-bucket",
                "test-bucket",
                "--output-dir",
                str(temp_output_dir / "out"),
                "--dry-run",
            ],
        ),
        patch("ca_operations.scripts.rotate_intermediate_ca.rotate_intermediate_ca") as mock_rotate,
        patch("ca_operations.scripts.rotate_intermediate_ca.SSMClient") as mock_ssm_cls,
        patch("ca_operations.scripts.rotate_intermediate_ca.DynamoDBClient"),
        patch("ca_operations.scripts.rotate_intermediate_ca.S3Client"),
    ):
        mock_ssm_cls.return_value.get_root_ca.return_value = (root_key_pem, root_cert_pem)

        from ca_operations.lib.models import RotationResult

        mock_rotate.return_value = RotationResult(
            reissued_count=0,
            revoked_count=0,
            failed_count=0,
            new_intermediate_serial="ABC",
            truststore_version_id="",
            reissued_serials=[],
            failed_client_ids=[],
        )
        exit_code = main()

    assert exit_code == 0
    mock_ssm_cls.return_value.get_root_ca.assert_called_once_with("custom-project", "sandbox")
