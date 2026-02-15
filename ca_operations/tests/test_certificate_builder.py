"""Tests for certificate builder module."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.cert_utils import generate_private_key, validate_certificate_chain
from ca_operations.lib.certificate_builder import CertificateBuilder
from ca_operations.lib.config import DistinguishedName


class TestReissueClientCertificate:
    """Tests for CertificateBuilder.reissue_client_certificate."""

    def test_reissue_preserves_subject(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued certificate should have same subject as original."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        assert reissued.subject == client_cert.subject

    def test_reissue_preserves_public_key(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued certificate should have same public key as original."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        # Compare public key numbers
        orig_pub = client_cert.public_key()
        new_pub = reissued.public_key()
        assert orig_pub.public_numbers() == new_pub.public_numbers()  # type: ignore[union-attr]

    def test_reissue_generates_new_serial(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued certificate should have different serial number."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        assert reissued.serial_number != client_cert.serial_number

    def test_reissue_with_new_intermediate(
        self,
        client_cert: x509.Certificate,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
    ) -> None:
        """Re-issued cert should chain to new intermediate CA."""
        # Create a brand new intermediate CA
        new_intermediate_key = generate_private_key(key_size=2048)
        new_intermediate_dn = DistinguishedName(
            country="GB",
            state="London",
            locality="London",
            organization="Test Org",
            organizational_unit="Test Unit",
            common_name="New Intermediate CA",
        )
        new_intermediate_csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(new_intermediate_dn.to_x509_name())
            .sign(new_intermediate_key, hashes.SHA256())
        )
        new_intermediate_cert = CertificateBuilder.build_intermediate_ca(
            csr=new_intermediate_csr,
            root_cert=root_cert,
            root_key=root_key,
            validity_years=1,
        )

        # Re-issue with new intermediate
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=new_intermediate_cert,
            new_issuer_key=new_intermediate_key,
            validity_days=30,
        )

        # Verify chain: reissued -> new_intermediate -> root
        assert validate_certificate_chain(reissued, new_intermediate_cert, root_cert)

    def test_reissue_sets_correct_issuer(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued cert issuer should match new intermediate subject."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        assert reissued.issuer == intermediate_cert.subject

    def test_reissue_sets_ca_false(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued cert should have CA:FALSE constraint."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        bc = reissued.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_reissue_sets_key_usage(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Re-issued cert should have digital_signature and key_encipherment."""
        reissued = CertificateBuilder.reissue_client_certificate(
            original_cert=client_cert,
            new_issuer_cert=intermediate_cert,
            new_issuer_key=intermediate_key,
            validity_days=30,
        )
        ku = reissued.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is True
        assert ku.value.key_cert_sign is False


class TestBuildRootCA:
    """Tests for CertificateBuilder.build_root_ca."""

    def test_root_ca_is_self_signed(self, root_cert: x509.Certificate) -> None:
        """Root CA issuer must equal subject (self-signed)."""
        assert root_cert.issuer == root_cert.subject

    def test_root_ca_basic_constraints(self, root_cert: x509.Certificate) -> None:
        """Root CA must have CA=True, pathlen=None."""
        bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length is None

    def test_root_ca_key_usage(self, root_cert: x509.Certificate) -> None:
        """Root CA must have key_cert_sign=True, crl_sign=True, digital_signature=False."""
        ku = root_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.value.digital_signature is False

    def test_root_ca_validity_period(
        self, root_key: RSAPrivateKey, root_dn: DistinguishedName
    ) -> None:
        """Root CA validity matches requested years."""
        validity_years = 5
        before = datetime.now(UTC)
        cert = CertificateBuilder.build_root_ca(
            subject_dn=root_dn, private_key=root_key, validity_years=validity_years
        )
        expected_not_after = before + timedelta(days=validity_years * 365)
        # Allow 5-second delta for test execution time
        assert abs((cert.not_valid_after_utc - expected_not_after).total_seconds()) < 5

    def test_root_ca_subject_matches_dn(
        self, root_cert: x509.Certificate, root_dn: DistinguishedName
    ) -> None:
        """Root CA subject DN matches input DistinguishedName."""
        cn = root_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == root_dn.common_name
        org = root_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        assert org == root_dn.organization


class TestBuildIntermediateCA:
    """Tests for CertificateBuilder.build_intermediate_ca."""

    def test_issuer_matches_root_subject(
        self,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """Intermediate issuer must match root subject."""
        assert intermediate_cert.issuer == root_cert.subject

    def test_basic_constraints_ca_true_pathlen_zero(
        self, intermediate_cert: x509.Certificate
    ) -> None:
        """Intermediate must have CA=True, pathlen=0."""
        bc = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_key_usage(self, intermediate_cert: x509.Certificate) -> None:
        """Intermediate must have key_cert_sign=True, crl_sign=True."""
        ku = intermediate_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.value.digital_signature is False

    def test_raises_on_invalid_csr_signature(
        self,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        intermediate_dn: DistinguishedName,
    ) -> None:
        """build_intermediate_ca raises ValueError for tampered CSR."""
        # Tamper: rebuild with different key to invalidate signature
        tampered_key = generate_private_key(key_size=2048)
        tampered_csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(intermediate_dn.to_x509_name())
            .sign(tampered_key, hashes.SHA256())
        )
        # Since we can't easily create an invalid CSR with cryptography lib,
        # we mock validate_csr_signature to return False
        from unittest.mock import patch

        with (
            patch(
                "ca_operations.lib.certificate_builder.validate_csr_signature",
                return_value=False,
            ),
            pytest.raises(ValueError, match="CSR signature validation failed"),
        ):
            CertificateBuilder.build_intermediate_ca(
                csr=tampered_csr,
                root_cert=root_cert,
                root_key=root_key,
                validity_years=1,
            )

    def test_chain_validates_intermediate_to_root(
        self,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """Intermediate cert should be verifiable against root."""
        intermediate_cert.verify_directly_issued_by(root_cert)


class TestBuildClientCertificate:
    """Tests for CertificateBuilder.build_client_certificate."""

    def test_issuer_matches_intermediate_subject(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
    ) -> None:
        """Client cert issuer must match intermediate subject."""
        assert client_cert.issuer == intermediate_cert.subject

    def test_basic_constraints_ca_false(self, client_cert: x509.Certificate) -> None:
        """Client cert must have CA=False."""
        bc = client_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_key_usage_client(self, client_cert: x509.Certificate) -> None:
        """Client cert: digital_signature=True, key_encipherment=True, key_cert_sign=False."""
        ku = client_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is True
        assert ku.value.key_cert_sign is False

    def test_raises_on_invalid_csr(
        self,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
        client_dn: DistinguishedName,
    ) -> None:
        """build_client_certificate raises ValueError for invalid CSR."""
        key = generate_private_key(key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(client_dn.to_x509_name())
            .sign(key, hashes.SHA256())
        )
        from unittest.mock import patch

        with (
            patch(
                "ca_operations.lib.certificate_builder.validate_csr_signature",
                return_value=False,
            ),
            pytest.raises(ValueError, match="CSR signature validation failed"),
        ):
            CertificateBuilder.build_client_certificate(
                csr=csr,
                issuer_cert=intermediate_cert,
                issuer_key=intermediate_key,
                validity_days=30,
            )

    def test_validity_period_matches_input_days(
        self,
        client_csr: x509.CertificateSigningRequest,
        intermediate_cert: x509.Certificate,
        intermediate_key: RSAPrivateKey,
    ) -> None:
        """Client cert validity matches requested days."""
        validity_days = 60
        before = datetime.now(UTC)
        cert = CertificateBuilder.build_client_certificate(
            csr=client_csr,
            issuer_cert=intermediate_cert,
            issuer_key=intermediate_key,
            validity_days=validity_days,
        )
        expected_not_after = before + timedelta(days=validity_days)
        assert abs((cert.not_valid_after_utc - expected_not_after).total_seconds()) < 5

    def test_full_chain_validates(
        self,
        client_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate,
    ) -> None:
        """Full chain: client -> intermediate -> root validates."""
        assert validate_certificate_chain(client_cert, intermediate_cert, root_cert) is True
