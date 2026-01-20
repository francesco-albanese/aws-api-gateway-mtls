"""Tests for CAManager class."""

from pathlib import Path

import pytest
from cryptography import x509

from ca_operations.lib.ca_manager import CAManager
from ca_operations.lib.cert_utils import (
    deserialize_certificate,
    validate_certificate_chain,
)
from ca_operations.lib.config import CAConfig


class TestBootstrapCA:
    """Tests for bootstrap_ca() - Root + Intermediate CA generation."""

    def test_bootstrap_creates_root_and_intermediate_directories(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Bootstrap creates root-ca/ and intermediate-ca/ directories."""
        manager = CAManager(ca_config)
        manager.bootstrap_ca(temp_output_dir)

        assert (temp_output_dir / "root-ca").is_dir()
        assert (temp_output_dir / "intermediate-ca").is_dir()

    def test_bootstrap_creates_root_ca_files(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Bootstrap creates Root CA key, cert, and metadata files."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        assert result.root_key_path.exists()
        assert result.root_cert_path.exists()
        assert (temp_output_dir / "root-ca" / "metadata.json").exists()

    def test_bootstrap_creates_intermediate_ca_files(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Bootstrap creates Intermediate CA key, cert, CSR, and metadata files."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        assert result.intermediate_key_path.exists()
        assert result.intermediate_cert_path.exists()
        assert result.intermediate_csr_path.exists()
        assert (temp_output_dir / "intermediate-ca" / "metadata.json").exists()

    def test_bootstrap_root_signs_intermediate(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Root CA correctly signs Intermediate CA certificate."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        root_cert = deserialize_certificate(result.root_cert_path.read_bytes())
        intermediate_cert = deserialize_certificate(result.intermediate_cert_path.read_bytes())

        # Intermediate cert should be issued by Root CA
        intermediate_cert.verify_directly_issued_by(root_cert)

    def test_bootstrap_root_is_self_signed(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Root CA certificate is self-signed."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        root_cert = deserialize_certificate(result.root_cert_path.read_bytes())

        # Root cert should verify itself
        root_cert.verify_directly_issued_by(root_cert)

    def test_bootstrap_root_has_ca_basic_constraints(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Root CA has BasicConstraints with CA=true."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        root_cert = deserialize_certificate(result.root_cert_path.read_bytes())
        bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value

        assert bc.ca is True

    def test_bootstrap_intermediate_has_pathlen_0(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Intermediate CA has BasicConstraints with pathlen=0 (can only sign end-entity certs)."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        intermediate_cert = deserialize_certificate(result.intermediate_cert_path.read_bytes())
        bc = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value

        assert bc.ca is True
        assert bc.path_length == 0

    def test_bootstrap_serial_numbers_are_unique(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """Root and Intermediate CAs have unique serial numbers."""
        manager = CAManager(ca_config)
        result = manager.bootstrap_ca(temp_output_dir)

        assert result.root_serial != result.intermediate_serial


class TestCreateTruststore:
    """Tests for create_truststore() - PEM bundle creation."""

    def test_create_truststore_writes_bundle(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """create_truststore writes bundle file to specified path."""
        manager = CAManager(ca_config)
        truststore_path = ca_files_on_disk / "truststore" / "bundle.pem"

        result = manager.create_truststore(ca_files_on_disk, truststore_path)

        assert result.exists()
        assert result == truststore_path

    def test_create_truststore_contains_both_certs(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Truststore bundle contains both Intermediate and Root CA certs."""
        manager = CAManager(ca_config)
        truststore_path = ca_files_on_disk / "truststore" / "bundle.pem"

        manager.create_truststore(ca_files_on_disk, truststore_path)
        bundle_content = truststore_path.read_bytes()

        # Should contain two certificates (two BEGIN CERTIFICATE markers)
        assert bundle_content.count(b"-----BEGIN CERTIFICATE-----") == 2
        assert bundle_content.count(b"-----END CERTIFICATE-----") == 2

    def test_create_truststore_order_intermediate_then_root(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Truststore bundle has Intermediate before Root (chain order)."""
        manager = CAManager(ca_config)
        truststore_path = ca_files_on_disk / "truststore" / "bundle.pem"

        manager.create_truststore(ca_files_on_disk, truststore_path)
        bundle_content = truststore_path.read_bytes()

        intermediate_pem = (
            ca_files_on_disk / "intermediate-ca" / "IntermediateCA.pem"
        ).read_bytes()
        root_pem = (ca_files_on_disk / "root-ca" / "RootCA.pem").read_bytes()

        # Intermediate should appear before Root in bundle
        intermediate_pos = bundle_content.find(intermediate_pem.split(b"\n")[1])
        root_pos = bundle_content.find(root_pem.split(b"\n")[1])

        assert intermediate_pos < root_pos

    def test_create_truststore_missing_intermediate_raises(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """create_truststore raises FileNotFoundError if Intermediate CA missing."""
        manager = CAManager(ca_config)
        truststore_path = temp_output_dir / "truststore" / "bundle.pem"

        with pytest.raises(FileNotFoundError, match="intermediate CA cert not found"):
            manager.create_truststore(temp_output_dir, truststore_path)

    def test_create_truststore_missing_root_raises(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """create_truststore raises FileNotFoundError if Root CA missing."""
        manager = CAManager(ca_config)

        # Create only intermediate dir
        intermediate_dir = temp_output_dir / "intermediate-ca"
        intermediate_dir.mkdir(parents=True)
        (intermediate_dir / "IntermediateCA.pem").write_bytes(b"dummy")

        truststore_path = temp_output_dir / "truststore" / "bundle.pem"

        with pytest.raises(FileNotFoundError, match="root CA cert not found"):
            manager.create_truststore(temp_output_dir, truststore_path)


class TestProvisionClientCertificate:
    """Tests for provision_client_certificate() - client cert generation."""

    def test_provision_creates_client_directory(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """provision_client_certificate creates client-specific directory."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        manager.provision_client_certificate(
            client_id="test-client-001",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        assert (output_dir / "test-client-001").is_dir()

    def test_provision_creates_all_client_files(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """provision_client_certificate creates key, cert, CSR, and metadata."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        result = manager.provision_client_certificate(
            client_id="test-client-001",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        assert result.key_path.exists()
        assert result.cert_path.exists()
        assert result.csr_path.exists()
        assert result.metadata_path.exists()

    def test_provision_client_signed_by_intermediate(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Client certificate is signed by Intermediate CA."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        result = manager.provision_client_certificate(
            client_id="test-client-001",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        client_cert = deserialize_certificate(result.cert_path.read_bytes())
        intermediate_cert = deserialize_certificate(
            (ca_files_on_disk / "intermediate-ca" / "IntermediateCA.pem").read_bytes()
        )

        client_cert.verify_directly_issued_by(intermediate_cert)

    def test_provision_full_chain_validates(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Full chain validates: client -> intermediate -> root."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        result = manager.provision_client_certificate(
            client_id="test-client-001",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        client_cert = deserialize_certificate(result.cert_path.read_bytes())
        intermediate_cert = deserialize_certificate(
            (ca_files_on_disk / "intermediate-ca" / "IntermediateCA.pem").read_bytes()
        )
        root_cert = deserialize_certificate(
            (ca_files_on_disk / "root-ca" / "RootCA.pem").read_bytes()
        )

        assert validate_certificate_chain(client_cert, intermediate_cert, root_cert)

    def test_provision_client_cn_matches_client_id(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Client certificate CN matches provided client_id."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        result = manager.provision_client_certificate(
            client_id="my-special-client",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        client_cert = deserialize_certificate(result.cert_path.read_bytes())
        cn = client_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

        assert cn == "my-special-client"

    def test_provision_client_not_a_ca(
        self,
        ca_files_on_disk: Path,
        ca_config: CAConfig,
    ) -> None:
        """Client certificate has CA=false (end-entity cert)."""
        manager = CAManager(ca_config)
        output_dir = ca_files_on_disk / "clients"

        result = manager.provision_client_certificate(
            client_id="test-client-001",
            ca_base_dir=ca_files_on_disk,
            output_dir=output_dir,
        )

        client_cert = deserialize_certificate(result.cert_path.read_bytes())
        bc = client_cert.extensions.get_extension_for_class(x509.BasicConstraints).value

        assert bc.ca is False

    def test_provision_missing_intermediate_key_raises(
        self,
        temp_output_dir: Path,
        ca_config: CAConfig,
    ) -> None:
        """provision_client_certificate raises if Intermediate CA key missing."""
        manager = CAManager(ca_config)

        with pytest.raises(FileNotFoundError, match="intermediate CA key not found"):
            manager.provision_client_certificate(
                client_id="test-client",
                ca_base_dir=temp_output_dir,
                output_dir=temp_output_dir / "clients",
            )
