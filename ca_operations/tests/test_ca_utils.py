"""Tests for ca_utils module."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.ca_utils import build_dn_from_config, create_intermediate_ca
from ca_operations.lib.config import CAConfig


class TestBuildDnFromConfig:
    """Tests for build_dn_from_config."""

    def test_builds_dn_with_config_fields(self, ca_config: CAConfig) -> None:
        """DN fields should match config values."""
        dn = build_dn_from_config(ca_config, common_name="Test CN")
        assert dn.country == ca_config.country
        assert dn.state == ca_config.state
        assert dn.locality == ca_config.locality
        assert dn.organization == ca_config.organization
        assert dn.organizational_unit == ca_config.organizational_unit
        assert dn.common_name == "Test CN"

    def test_common_name_overrides_config(self, ca_config: CAConfig) -> None:
        """Provided common_name should be used, not derived from config."""
        dn = build_dn_from_config(ca_config, common_name="Custom CA Name")
        x509_name = dn.to_x509_name()
        cn = x509_name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == "Custom CA Name"


class TestCreateIntermediateCA:
    """Tests for create_intermediate_ca."""

    def test_returns_key_cert_csr_tuple(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """Should return (RSAPrivateKey, Certificate, CSR) tuple."""
        key, cert, csr = create_intermediate_ca(
            root_cert=root_cert, root_key=root_key, config=ca_config
        )
        assert isinstance(key, RSAPrivateKey)
        assert isinstance(cert, x509.Certificate)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_cert_signed_by_root(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """Intermediate cert issuer should match root subject."""
        _, cert, _ = create_intermediate_ca(
            root_cert=root_cert, root_key=root_key, config=ca_config
        )
        cert.verify_directly_issued_by(root_cert)

    def test_cert_is_ca_with_pathlen_zero(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """Intermediate cert should have CA=True, pathlen=0."""
        _, cert, _ = create_intermediate_ca(
            root_cert=root_cert, root_key=root_key, config=ca_config
        )
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True
        assert bc.path_length == 0

    def test_custom_common_name(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """Custom common_name should appear in cert subject."""
        _, cert, _ = create_intermediate_ca(
            root_cert=root_cert,
            root_key=root_key,
            config=ca_config,
            common_name="Rotated CA 2026-01-01",
        )
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == "Rotated CA 2026-01-01"

    def test_csr_subject_matches_cert_subject(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """CSR subject should match the issued cert subject."""
        _, cert, csr = create_intermediate_ca(
            root_cert=root_cert, root_key=root_key, config=ca_config
        )
        assert csr.subject == cert.subject

    def test_key_matches_cert_public_key(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        ca_config: CAConfig,
    ) -> None:
        """Private key should correspond to the cert's public key."""
        key, cert, _ = create_intermediate_ca(
            root_cert=root_cert, root_key=root_key, config=ca_config
        )
        assert key.public_key().public_numbers() == cert.public_key().public_numbers()  # type: ignore[union-attr]
