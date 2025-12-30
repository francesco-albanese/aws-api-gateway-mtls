"""Certificate builder for X.509 certificate construction."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .cert_utils import generate_serial_number
from .config import DistinguishedName


class CertificateBuilder:
    """Builds X.509 certificates for CA hierarchy and client certificates."""

    @staticmethod
    def build_root_ca(
        subject_dn: DistinguishedName,
        private_key: RSAPrivateKey,
        validity_years: int,
    ) -> x509.Certificate:
        """Build self-signed Root CA certificate.

        Args:
            subject_dn: Distinguished name for certificate subject
            private_key: RSA private key for signing
            validity_years: Certificate validity period in years

        Returns:
            Self-signed X.509 certificate with CA extensions
        """
        subject = subject_dn.to_x509_name()
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_years * 365)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(generate_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        return builder.sign(private_key, hashes.SHA256())

    @staticmethod
    def build_intermediate_ca(
        csr: x509.CertificateSigningRequest,
        root_cert: x509.Certificate,
        root_key: RSAPrivateKey,
        validity_years: int,
    ) -> x509.Certificate:
        """Build Intermediate CA certificate from CSR, signed by Root CA.

        Traditional PKI flow: CSR contains subject DN and public key.
        Signer validates CSR signature and issues certificate.

        Args:
            csr: Certificate signing request from intermediate CA
            root_cert: Root CA certificate (issuer)
            root_key: Root CA private key for signing
            validity_years: Certificate validity period in years

        Returns:
            X.509 certificate signed by Root CA with pathlen:0 constraint

        Raises:
            ValueError: If CSR signature is invalid
        """
        from .cert_utils import (
            extract_csr_public_key,
            extract_csr_subject,
            validate_csr_signature,
        )

        if not validate_csr_signature(csr):
            raise ValueError("CSR signature validation failed")

        subject = extract_csr_subject(csr)
        public_key = extract_csr_public_key(csr)

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_years * 365)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_cert.subject)
            .public_key(public_key)
            .serial_number(generate_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        return builder.sign(root_key, hashes.SHA256())

    @staticmethod
    def build_client_certificate(
        csr: x509.CertificateSigningRequest,
        issuer_cert: x509.Certificate,
        issuer_key: RSAPrivateKey,
        validity_days: int,
    ) -> x509.Certificate:
        """Build client certificate from CSR, signed by Intermediate CA.

        Traditional PKI flow: Client generates CSR with their DN and public key.
        CA validates CSR and issues certificate without ever seeing client's private key.

        Args:
            csr: Certificate signing request from client
            issuer_cert: Intermediate CA certificate (issuer)
            issuer_key: Intermediate CA private key for signing
            validity_days: Certificate validity period in days

        Returns:
            X.509 end-entity certificate signed by Intermediate CA

        Raises:
            ValueError: If CSR signature is invalid
        """
        from .cert_utils import (
            extract_csr_public_key,
            extract_csr_subject,
            validate_csr_signature,
        )

        if not validate_csr_signature(csr):
            raise ValueError("CSR signature validation failed")

        subject = extract_csr_subject(csr)
        public_key = extract_csr_public_key(csr)

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(public_key)
            .serial_number(generate_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=False,
            )
        )

        return builder.sign(issuer_key, hashes.SHA256())
