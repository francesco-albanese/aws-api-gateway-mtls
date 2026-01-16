"""Test fixtures for ca_operations tests."""

from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ca_operations.lib.cert_utils import (
    generate_private_key,
    serialize_certificate,
    serialize_private_key,
)
from ca_operations.lib.certificate_builder import CertificateBuilder
from ca_operations.lib.config import CAConfig, DistinguishedName


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Return temporary directory for test output artifacts."""
    return tmp_path


@pytest.fixture
def ca_config() -> CAConfig:
    """Return test CA configuration with shorter validity periods."""
    return CAConfig(
        country="GB",
        state="London",
        locality="London",
        organization="Test Org",
        organizational_unit="Test Unit",
        root_validity_years=1,
        intermediate_validity_years=1,
        client_validity_days=30,
        key_size=2048,  # Faster for tests
    )


@pytest.fixture
def root_key() -> RSAPrivateKey:
    """Generate RSA private key for Root CA."""
    return generate_private_key(key_size=2048)


@pytest.fixture
def root_dn() -> DistinguishedName:
    """Return test Root CA distinguished name."""
    return DistinguishedName(
        country="GB",
        state="London",
        locality="London",
        organization="Test Org",
        organizational_unit="Test Unit",
        common_name="Test Root CA",
    )


@pytest.fixture
def root_cert(root_key: RSAPrivateKey, root_dn: DistinguishedName) -> x509.Certificate:
    """Generate self-signed Root CA certificate."""
    return CertificateBuilder.build_root_ca(
        subject_dn=root_dn,
        private_key=root_key,
        validity_years=1,
    )


@pytest.fixture
def intermediate_key() -> RSAPrivateKey:
    """Generate RSA private key for Intermediate CA."""
    return generate_private_key(key_size=2048)


@pytest.fixture
def intermediate_dn() -> DistinguishedName:
    """Return test Intermediate CA distinguished name."""
    return DistinguishedName(
        country="GB",
        state="London",
        locality="London",
        organization="Test Org",
        organizational_unit="Test Unit",
        common_name="Test Intermediate CA",
    )


@pytest.fixture
def intermediate_csr(
    intermediate_key: RSAPrivateKey,
    intermediate_dn: DistinguishedName,
) -> x509.CertificateSigningRequest:
    """Generate Intermediate CA CSR."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(intermediate_dn.to_x509_name())
        .sign(intermediate_key, hashes.SHA256())
    )


@pytest.fixture
def intermediate_cert(
    intermediate_csr: x509.CertificateSigningRequest,
    root_cert: x509.Certificate,
    root_key: RSAPrivateKey,
) -> x509.Certificate:
    """Generate Intermediate CA certificate signed by Root CA."""
    return CertificateBuilder.build_intermediate_ca(
        csr=intermediate_csr,
        root_cert=root_cert,
        root_key=root_key,
        validity_years=1,
    )


@pytest.fixture
def client_key() -> RSAPrivateKey:
    """Generate RSA private key for client certificate."""
    return generate_private_key(key_size=2048)


@pytest.fixture
def client_dn() -> DistinguishedName:
    """Return test client distinguished name."""
    return DistinguishedName(
        country="GB",
        state="London",
        locality="London",
        organization="Test Org",
        organizational_unit="Test Unit",
        common_name="test-client-001",
    )


@pytest.fixture
def client_csr(
    client_key: RSAPrivateKey,
    client_dn: DistinguishedName,
) -> x509.CertificateSigningRequest:
    """Generate client certificate CSR."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(client_dn.to_x509_name())
        .sign(client_key, hashes.SHA256())
    )


@pytest.fixture
def client_cert(
    client_csr: x509.CertificateSigningRequest,
    intermediate_cert: x509.Certificate,
    intermediate_key: RSAPrivateKey,
) -> x509.Certificate:
    """Generate client certificate signed by Intermediate CA."""
    return CertificateBuilder.build_client_certificate(
        csr=client_csr,
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
        validity_days=30,
    )


@pytest.fixture
def ca_files_on_disk(
    temp_output_dir: Path,
    root_key: RSAPrivateKey,
    root_cert: x509.Certificate,
    intermediate_key: RSAPrivateKey,
    intermediate_cert: x509.Certificate,
) -> Generator[Path]:
    """Write CA files to disk and return base directory.

    Creates:
        {temp_dir}/root-ca/RootCA.pem
        {temp_dir}/root-ca/RootCA.key
        {temp_dir}/intermediate-ca/IntermediateCA.pem
        {temp_dir}/intermediate-ca/IntermediateCA.key
    """
    root_dir = temp_output_dir / "root-ca"
    intermediate_dir = temp_output_dir / "intermediate-ca"
    root_dir.mkdir(parents=True, exist_ok=True)
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    (root_dir / "RootCA.pem").write_bytes(serialize_certificate(root_cert))
    (root_dir / "RootCA.key").write_bytes(serialize_private_key(root_key))
    (intermediate_dir / "IntermediateCA.pem").write_bytes(serialize_certificate(intermediate_cert))
    (intermediate_dir / "IntermediateCA.key").write_bytes(serialize_private_key(intermediate_key))

    yield temp_output_dir
