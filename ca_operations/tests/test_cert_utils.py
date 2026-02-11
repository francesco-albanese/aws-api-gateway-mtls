"""Tests for cert_utils module."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from ca_operations.lib.cert_utils import (
    create_truststore_bundle,
    deserialize_certificate,
    deserialize_csr,
    deserialize_private_key,
    extract_certificate_metadata,
    extract_csr_public_key,
    extract_csr_subject,
    generate_private_key,
    generate_serial_number,
    get_certificate_serial_hex,
    serialize_certificate,
    serialize_csr,
    serialize_private_key,
    validate_certificate_chain,
    validate_csr_signature,
)


class TestKeyGeneration:
    """Tests for RSA key generation."""

    def test_generate_private_key_default_size(self) -> None:
        """generate_private_key creates 4096-bit key by default."""
        key = generate_private_key()
        assert key.key_size == 4096

    def test_generate_private_key_custom_size(self) -> None:
        """generate_private_key respects custom key size."""
        key = generate_private_key(key_size=2048)
        assert key.key_size == 2048

    def test_generate_private_key_returns_rsa(self) -> None:
        """generate_private_key returns RSAPrivateKey type."""
        key = generate_private_key(key_size=2048)
        assert isinstance(key, RSAPrivateKey)


class TestKeySerialization:
    """Tests for key serialization/deserialization."""

    def test_serialize_private_key_pem_format(self) -> None:
        """serialize_private_key outputs PEM format."""
        key = generate_private_key(key_size=2048)
        pem = serialize_private_key(key)

        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert b"-----END PRIVATE KEY-----" in pem

    def test_key_roundtrip_preserves_key(self) -> None:
        """serialize -> deserialize preserves key material."""
        key = generate_private_key(key_size=2048)
        pem = serialize_private_key(key)
        restored = deserialize_private_key(pem)

        # Public keys should match
        original_pub = key.public_key().public_numbers()
        restored_pub = restored.public_key().public_numbers()

        assert original_pub.n == restored_pub.n
        assert original_pub.e == restored_pub.e


class TestCertificateSerialization:
    """Tests for certificate serialization/deserialization."""

    def test_serialize_certificate_pem_format(
        self,
        root_cert: x509.Certificate,
    ) -> None:
        """serialize_certificate outputs PEM format."""
        pem = serialize_certificate(root_cert)

        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert b"-----END CERTIFICATE-----" in pem

    def test_certificate_roundtrip_preserves_cert(
        self,
        root_cert: x509.Certificate,
    ) -> None:
        """serialize -> deserialize preserves certificate."""
        pem = serialize_certificate(root_cert)
        restored = deserialize_certificate(pem)

        assert root_cert.serial_number == restored.serial_number
        assert root_cert.subject == restored.subject


class TestSerialNumber:
    """Tests for certificate serial number generation."""

    def test_generate_serial_number_is_positive(self) -> None:
        """Serial numbers are positive integers."""
        serial = generate_serial_number()
        assert serial > 0

    def test_generate_serial_number_is_unique(self) -> None:
        """Multiple calls generate unique serial numbers."""
        serials = [generate_serial_number() for _ in range(100)]
        assert len(set(serials)) == 100

    def test_get_certificate_serial_hex_format(
        self,
        root_cert: x509.Certificate,
    ) -> None:
        """get_certificate_serial_hex returns colon-separated hex."""
        serial_hex = get_certificate_serial_hex(root_cert)

        # Should contain colons between bytes
        assert ":" in serial_hex

        # Each part should be 2 hex chars
        parts = serial_hex.split(":")
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # Should be valid hex

    def test_get_certificate_serial_hex_uppercase(
        self,
        root_cert: x509.Certificate,
    ) -> None:
        """Serial hex uses uppercase letters."""
        serial_hex = get_certificate_serial_hex(root_cert)
        # All alpha chars should be uppercase
        assert serial_hex == serial_hex.upper()


class TestCertificateMetadata:
    """Tests for certificate metadata extraction."""

    def test_extract_metadata_has_serial_number(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes serialNumber in hex format."""
        metadata = extract_certificate_metadata(client_cert)

        assert "serialNumber" in metadata
        assert isinstance(metadata["serialNumber"], str)
        assert ":" in str(metadata["serialNumber"])

    def test_extract_metadata_has_client_name(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes clientName from certificate CN."""
        metadata = extract_certificate_metadata(client_cert)

        assert "clientName" in metadata
        assert metadata["clientName"] == "test-client-001"

    def test_extract_metadata_has_validity_dates(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes notBefore and expiry timestamps."""
        metadata = extract_certificate_metadata(client_cert)

        assert "notBefore" in metadata
        assert "expiry" in metadata

        # Should be ISO8601 format (parseable)
        datetime.fromisoformat(str(metadata["notBefore"]))
        datetime.fromisoformat(str(metadata["expiry"]))

    def test_extract_metadata_has_status_active(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes status='active' by default."""
        metadata = extract_certificate_metadata(client_cert)

        assert metadata["status"] == "active"

    def test_extract_metadata_has_issued_at(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes issuedAt timestamp."""
        before = datetime.now(UTC)
        metadata = extract_certificate_metadata(client_cert)
        after = datetime.now(UTC)

        issued_at = datetime.fromisoformat(str(metadata["issuedAt"]))

        # Should be between before and after
        assert before <= issued_at <= after

    def test_extract_metadata_has_ttl(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes ttl (unix timestamp for DynamoDB expiration)."""
        metadata = extract_certificate_metadata(client_cert)

        assert "ttl" in metadata
        assert isinstance(metadata["ttl"], int)

        # TTL should be expiry + 90 days
        expiry = datetime.fromisoformat(str(metadata["expiry"]))
        expected_ttl = int((expiry + timedelta(days=90)).timestamp())

        # Allow small rounding difference
        assert abs(int(metadata["ttl"]) - expected_ttl) < 2

    def test_extract_metadata_with_client_id(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata includes client_id when provided."""
        metadata = extract_certificate_metadata(client_cert, client_id="my-client-id")

        assert metadata["client_id"] == "my-client-id"

    def test_extract_metadata_without_client_id(
        self,
        client_cert: x509.Certificate,
    ) -> None:
        """Metadata excludes client_id when not provided."""
        metadata = extract_certificate_metadata(client_cert)

        assert "client_id" not in metadata


class TestTruststoreBundle:
    """Tests for truststore bundle creation."""

    def test_create_truststore_bundle_concatenates(
        self,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """create_truststore_bundle concatenates certs with newline."""
        intermediate_pem = serialize_certificate(intermediate_cert)
        root_pem = serialize_certificate(root_cert)

        bundle = create_truststore_bundle(intermediate_pem, root_pem)

        assert intermediate_pem in bundle
        assert root_pem in bundle

    def test_create_truststore_bundle_order(
        self,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """Bundle has intermediate before root."""
        intermediate_pem = serialize_certificate(intermediate_cert)
        root_pem = serialize_certificate(root_cert)

        bundle = create_truststore_bundle(intermediate_pem, root_pem)

        intermediate_pos = bundle.find(intermediate_pem)
        root_pos = bundle.find(root_pem)

        assert intermediate_pos < root_pos

    def test_create_truststore_bundle_parseable(
        self,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """Bundle can be parsed to extract both certificates."""
        intermediate_pem = serialize_certificate(intermediate_cert)
        root_pem = serialize_certificate(root_cert)

        bundle = create_truststore_bundle(intermediate_pem, root_pem)

        # Should contain two complete PEM blocks
        assert bundle.count(b"-----BEGIN CERTIFICATE-----") == 2


class TestChainValidation:
    """Tests for certificate chain validation."""

    def test_validate_valid_chain(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """validate_certificate_chain returns True for valid chain."""
        result = validate_certificate_chain(client_cert, intermediate_cert, root_cert)
        assert result is True

    def test_validate_invalid_chain_wrong_intermediate(
        self,
        client_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """validate_certificate_chain returns False if intermediate doesn't match."""
        # Use root cert in place of intermediate (wrong issuer)
        result = validate_certificate_chain(client_cert, root_cert, root_cert)
        assert result is False

    def test_validate_self_signed_as_chain(
        self,
        root_cert: x509.Certificate,
    ) -> None:
        """Self-signed cert can validate as its own chain."""
        result = validate_certificate_chain(root_cert, root_cert, root_cert)
        assert result is True


class TestCSROperations:
    """Tests for CSR extraction and validation."""

    def test_extract_csr_subject(
        self,
        client_csr: x509.CertificateSigningRequest,
        client_dn,
    ) -> None:
        """extract_csr_subject returns CSR subject."""
        subject = extract_csr_subject(client_csr)

        cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == client_dn.common_name

    def test_extract_csr_public_key(
        self,
        client_csr: x509.CertificateSigningRequest,
    ) -> None:
        """extract_csr_public_key returns RSA public key."""
        pub_key = extract_csr_public_key(client_csr)
        assert isinstance(pub_key, RSAPublicKey)

    def test_validate_csr_signature_valid(
        self,
        client_csr: x509.CertificateSigningRequest,
    ) -> None:
        """validate_csr_signature returns True for valid CSR."""
        assert validate_csr_signature(client_csr) is True

    def test_csr_roundtrip(
        self,
        client_csr: x509.CertificateSigningRequest,
    ) -> None:
        """serialize -> deserialize preserves CSR."""
        pem = serialize_csr(client_csr)
        restored = deserialize_csr(pem)

        assert client_csr.subject == restored.subject


class TestDeserializePrivateKeyEdgeCases:
    """Tests for deserialize_private_key with non-RSA keys."""

    def test_ec_key_raises_value_error(self) -> None:
        """deserialize_private_key raises ValueError for EC private key."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pem = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="expected RSA private key"):
            deserialize_private_key(ec_pem)


class TestExtractCSRPublicKeyEdgeCases:
    """Tests for extract_csr_public_key with non-RSA CSR."""

    def test_ec_csr_raises_value_error(self) -> None:
        """extract_csr_public_key raises ValueError for EC-based CSR."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ec-test")]))
            .sign(ec_key, hashes.SHA256())
        )
        with pytest.raises(ValueError, match="CSR public key must be RSA type"):
            extract_csr_public_key(csr)
