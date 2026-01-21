"""Tests for certificate builder module."""

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
