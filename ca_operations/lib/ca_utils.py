"""Reusable CA utility functions for intermediate CA creation."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .cert_utils import generate_private_key
from .certificate_builder import CertificateBuilder
from .config import CAConfig, DistinguishedName


def build_dn_from_config(config: CAConfig, common_name: str) -> DistinguishedName:
    """Build DN from CAConfig fields + common_name."""
    return DistinguishedName(
        country=config.country,
        state=config.state,
        locality=config.locality,
        organization=config.organization,
        organizational_unit=config.organizational_unit,
        common_name=common_name,
    )


def create_intermediate_ca(
    root_cert: x509.Certificate,
    root_key: RSAPrivateKey,
    config: CAConfig,
    common_name: str = "Francesco Albanese Issuing CA",
) -> tuple[RSAPrivateKey, x509.Certificate, x509.CertificateSigningRequest]:
    """Generate new intermediate CA key, CSR, cert signed by root.

    Args:
        root_cert: Root CA certificate (issuer)
        root_key: Root CA private key for signing
        config: CA configuration with key size and validity
        common_name: CN for the intermediate CA

    Returns:
        Tuple of (intermediate_key, intermediate_cert, csr)
    """
    intermediate_key = generate_private_key(config.key_size)
    intermediate_dn = build_dn_from_config(config, common_name)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(intermediate_dn.to_x509_name())
        .sign(intermediate_key, hashes.SHA256())
    )

    intermediate_cert = CertificateBuilder.build_intermediate_ca(
        csr=csr,
        root_cert=root_cert,
        root_key=root_key,
        validity_years=config.intermediate_validity_years,
    )

    return intermediate_key, intermediate_cert, csr
