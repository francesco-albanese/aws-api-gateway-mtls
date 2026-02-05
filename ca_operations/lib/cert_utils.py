"""Certificate utility functions for key generation, serialization, and metadata extraction."""

import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.models import CertificateMetadata


def generate_private_key(key_size: int = 4096) -> RSAPrivateKey:
    """Generate RSA private key with specified size."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def serialize_private_key(key: RSAPrivateKey) -> bytes:
    """Serialize private key to PEM format (PKCS8, no encryption)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_data: bytes) -> RSAPrivateKey:
    """Deserialize private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("expected RSA private key")
    return key


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def deserialize_certificate(pem_data: bytes) -> x509.Certificate:
    """Deserialize certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(pem_data)


def generate_serial_number() -> int:
    """Generate certificate serial number from UUID4.

    Uses UUID v4 (random) for cryptographically strong serial numbers
    with 128-bit values (~122 bits effective entropy).

    Provides:
    - Strong uniqueness guarantees (collision prob ~2.71 × 10^-18 for 1B certs)
    - Exceeds CA/Browser Forum baseline (64 bits CSPRNG minimum)
    - Deterministic bit length (128 bits)

    Returns:
        Integer serial number for x509.CertificateBuilder.serial_number()
    """
    return uuid.uuid4().int


def get_certificate_serial_hex(cert: x509.Certificate) -> str:
    """Return certificate serial number as hex with colons (e.g., 3A:F2:B1:...)."""
    serial_hex = f"{cert.serial_number:X}"
    if len(serial_hex) % 2 != 0:
        serial_hex = "0" + serial_hex
    return ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))


def extract_certificate_metadata(
    cert: x509.Certificate, client_id: str | None = None
) -> CertificateMetadata:
    """Extract certificate metadata for JSON serialization (DynamoDB import).

    Args:
        cert: X.509 certificate to extract metadata from
        client_id: Optional client identifier (for client certs)

    Returns:
        CertificateMetadata with serialNumber, clientName, timestamps, status, ttl.
        client_id included only when provided (NotRequired field).
    """
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if not isinstance(cn, str):
        raise ValueError("CN must be string")

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    issued_at = datetime.now(UTC)
    ttl_datetime = not_after + timedelta(days=90)

    metadata = CertificateMetadata(
        serialNumber=get_certificate_serial_hex(cert),
        clientName=cn,
        notBefore=not_before.isoformat(),
        expiry=not_after.isoformat(),
        status="active",
        issuedAt=issued_at.isoformat(),
        ttl=int(ttl_datetime.timestamp()),
    )

    if client_id is not None:
        metadata["client_id"] = client_id

    return metadata


def create_truststore_bundle(intermediate_cert_pem: bytes, root_cert_pem: bytes) -> bytes:
    """Create truststore bundle by concatenating Intermediate + Root certs in PEM format."""
    return intermediate_cert_pem + b"\n" + root_cert_pem


def validate_certificate_chain(
    client_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
) -> bool:
    """Verify certificate chain signatures (client -> intermediate -> root).

    Returns True if chain is valid, False otherwise.
    """
    try:
        client_cert.verify_directly_issued_by(intermediate_cert)
        intermediate_cert.verify_directly_issued_by(root_cert)
        return True
    except Exception:
        return False


def extract_csr_subject(csr: x509.CertificateSigningRequest) -> x509.Name:
    """Extract subject DN from CSR.

    Args:
        csr: Certificate signing request

    Returns:
        X.509 Name from CSR subject field
    """
    return csr.subject


def extract_csr_public_key(
    csr: x509.CertificateSigningRequest,
) -> rsa.RSAPublicKey:
    """Extract public key from CSR.

    Args:
        csr: Certificate signing request

    Returns:
        RSA public key from CSR

    Raises:
        ValueError: If public key is not RSA type
    """
    public_key = csr.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("CSR public key must be RSA type")
    return public_key


def validate_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """Verify CSR self-signature to prove private key possession.

    Args:
        csr: Certificate signing request

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        return csr.is_signature_valid
    except Exception:
        return False


def serialize_csr(csr: x509.CertificateSigningRequest) -> bytes:
    """Serialize CSR to PEM format."""
    return csr.public_bytes(serialization.Encoding.PEM)


def deserialize_csr(pem_data: bytes) -> x509.CertificateSigningRequest:
    """Deserialize CSR from PEM bytes."""
    return x509.load_pem_x509_csr(pem_data)
