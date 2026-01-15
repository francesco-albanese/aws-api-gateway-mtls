"""CA manager for certificate authority operations."""

import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .cert_utils import (
    create_truststore_bundle,
    deserialize_certificate,
    deserialize_private_key,
    extract_certificate_metadata,
    generate_private_key,
    serialize_certificate,
    serialize_private_key,
)
from .certificate_builder import CertificateBuilder
from .config import CAConfig, DistinguishedName
from .models import BootstrapResult, ClientCertResult
from .ssm_client import SSMClient


class CAManager:
    """Certificate Authority manager for CA operations."""

    def __init__(self, config: CAConfig) -> None:
        """Initialize CA manager with configuration.

        Args:
            config: CA configuration with validity periods and DN template
        """
        self.config = config

    def bootstrap_ca(self, output_base_dir: Path) -> BootstrapResult:
        """Bootstrap Root CA and Intermediate CA, writing artifacts to filesystem.

        Generates:
            - Root CA private key and self-signed certificate
            - Intermediate CA private key, CSR, and certificate signed by Root CA
            - Metadata JSON files with serial numbers and validity dates

        Args:
            output_base_dir: Base directory for output artifacts

        Returns:
            BootstrapResult with file paths and serial numbers
        """
        root_dir = output_base_dir / "root-ca"
        intermediate_dir = output_base_dir / "intermediate-ca"
        root_dir.mkdir(parents=True, exist_ok=True)
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        root_key = generate_private_key(self.config.key_size)
        root_dn = DistinguishedName(
            country=self.config.country,
            state=self.config.state,
            locality=self.config.locality,
            organization=self.config.organization,
            organizational_unit=self.config.organizational_unit,
            common_name="Francesco Albanese Root CA",
        )
        root_cert = CertificateBuilder.build_root_ca(
            subject_dn=root_dn,
            private_key=root_key,
            validity_years=self.config.root_validity_years,
        )

        root_key_path = root_dir / "RootCA.key"
        root_cert_path = root_dir / "RootCA.pem"
        root_metadata_path = root_dir / "metadata.json"

        root_key_path.write_bytes(serialize_private_key(root_key))
        root_cert_path.write_bytes(serialize_certificate(root_cert))

        root_metadata = extract_certificate_metadata(root_cert)
        root_metadata_path.write_text(json.dumps(root_metadata, indent=2))

        intermediate_key = generate_private_key(self.config.key_size)
        intermediate_dn = DistinguishedName(
            country=self.config.country,
            state=self.config.state,
            locality=self.config.locality,
            organization=self.config.organization,
            organizational_unit=self.config.organizational_unit,
            common_name="Francesco Albanese Issuing CA",
        )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(intermediate_dn.to_x509_name())
            .sign(intermediate_key, hashes.SHA256())
        )

        intermediate_cert = CertificateBuilder.build_intermediate_ca(
            csr=csr,
            root_cert=root_cert,
            root_key=root_key,
            validity_years=self.config.intermediate_validity_years,
        )

        intermediate_key_path = intermediate_dir / "IntermediateCA.key"
        intermediate_cert_path = intermediate_dir / "IntermediateCA.pem"
        intermediate_csr_path = intermediate_dir / "IntermediateCA.csr"
        intermediate_metadata_path = intermediate_dir / "metadata.json"

        intermediate_key_path.write_bytes(serialize_private_key(intermediate_key))
        intermediate_cert_path.write_bytes(serialize_certificate(intermediate_cert))
        intermediate_csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        intermediate_metadata = extract_certificate_metadata(intermediate_cert)
        intermediate_metadata_path.write_text(json.dumps(intermediate_metadata, indent=2))

        return BootstrapResult(
            root_key_path=root_key_path,
            root_cert_path=root_cert_path,
            root_serial=str(root_metadata["serialNumber"]),
            intermediate_key_path=intermediate_key_path,
            intermediate_cert_path=intermediate_cert_path,
            intermediate_csr_path=intermediate_csr_path,
            intermediate_serial=str(intermediate_metadata["serialNumber"]),
        )

    def create_truststore(self, output_base_dir: Path, truststore_path: Path) -> Path:
        """Create truststore bundle (Intermediate + Root) for S3 upload.

        Args:
            output_base_dir: Base directory containing CA certificates
            truststore_path: Output path for truststore bundle

        Returns:
            Path to created truststore file

        Raises:
            FileNotFoundError: If CA certificates not found
        """
        intermediate_cert_path = output_base_dir / "intermediate-ca" / "IntermediateCA.pem"
        root_cert_path = output_base_dir / "root-ca" / "RootCA.pem"

        if not intermediate_cert_path.exists():
            raise FileNotFoundError(f"intermediate CA cert not found: {intermediate_cert_path}")
        if not root_cert_path.exists():
            raise FileNotFoundError(f"root CA cert not found: {root_cert_path}")

        intermediate_pem = intermediate_cert_path.read_bytes()
        root_pem = root_cert_path.read_bytes()

        bundle = create_truststore_bundle(intermediate_pem, root_pem)

        truststore_path.parent.mkdir(parents=True, exist_ok=True)
        truststore_path.write_bytes(bundle)

        return truststore_path

    def provision_client_certificate(
        self,
        client_id: str,
        ca_base_dir: Path,
        output_dir: Path,
    ) -> ClientCertResult:
        """Provision client certificate signed by Intermediate CA.

        Generates:
            - Client private key
            - CSR with client_id as CN
            - Certificate signed by Intermediate CA
            - Metadata JSON for DynamoDB import

        Args:
            client_id: Client identifier (used as CN in certificate)
            ca_base_dir: Base directory containing CA certificates and keys
            output_dir: Output directory for client artifacts

        Returns:
            ClientCertResult with file paths and serial number

        Raises:
            FileNotFoundError: If Intermediate CA key or cert not found
        """
        intermediate_key_path = ca_base_dir / "intermediate-ca" / "IntermediateCA.key"
        intermediate_cert_path = ca_base_dir / "intermediate-ca" / "IntermediateCA.pem"

        if not intermediate_key_path.exists():
            raise FileNotFoundError(f"intermediate CA key not found: {intermediate_key_path}")
        if not intermediate_cert_path.exists():
            raise FileNotFoundError(f"intermediate CA cert not found: {intermediate_cert_path}")

        intermediate_key = deserialize_private_key(intermediate_key_path.read_bytes())
        intermediate_cert = deserialize_certificate(intermediate_cert_path.read_bytes())

        client_key = generate_private_key(self.config.key_size)
        client_dn = DistinguishedName(
            country=self.config.country,
            state=self.config.state,
            locality=self.config.locality,
            organization=self.config.organization,
            organizational_unit=self.config.organizational_unit,
            common_name=client_id,
        )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(client_dn.to_x509_name())
            .sign(client_key, hashes.SHA256())
        )

        client_cert = CertificateBuilder.build_client_certificate(
            csr=csr,
            issuer_cert=intermediate_cert,
            issuer_key=intermediate_key,
            validity_days=self.config.client_validity_days,
        )

        client_dir = output_dir / client_id
        client_dir.mkdir(parents=True, exist_ok=True)

        key_path = client_dir / "client.key"
        cert_path = client_dir / "client.pem"
        csr_path = client_dir / "client.csr"
        metadata_path = client_dir / "metadata.json"

        key_path.write_bytes(serialize_private_key(client_key))
        cert_path.write_bytes(serialize_certificate(client_cert))
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        metadata = extract_certificate_metadata(client_cert, client_id=client_id)
        metadata_path.write_text(json.dumps(metadata, indent=2))

        serial_number = metadata["serialNumber"]
        if not isinstance(serial_number, str):
            raise ValueError("serial number must be string")

        return ClientCertResult(
            key_path=key_path,
            cert_path=cert_path,
            csr_path=csr_path,
            metadata_path=metadata_path,
            serial_number=serial_number,
        )

    def provision_client_certificate_from_ssm(
        self,
        client_id: str,
        account: str,
        ssm_client: SSMClient,
        output_dir: Path,
        project_name: str = "apigw-mtls",
    ) -> ClientCertResult:
        """Provision client certificate using Intermediate CA from SSM.

        Fetches intermediate CA from SSM Parameter Store, generates client
        certificate, and writes artifacts to filesystem for Terraform to upload.

        Args:
            client_id: Client identifier (used as CN in certificate)
            account: Account/environment name (e.g., 'sandbox')
            ssm_client: SSM client for fetching intermediate CA
            output_dir: Output directory for client artifacts
            project_name: Project name for SSM path prefix

        Returns:
            ClientCertResult with file paths and serial number

        Raises:
            ValueError: If intermediate CA not found in SSM
        """
        intermediate_key_pem, intermediate_cert_pem = ssm_client.get_intermediate_ca(
            project_name=project_name, account=account
        )

        intermediate_key = deserialize_private_key(intermediate_key_pem)
        intermediate_cert = deserialize_certificate(intermediate_cert_pem)

        client_key = generate_private_key(self.config.key_size)
        client_dn = DistinguishedName(
            country=self.config.country,
            state=self.config.state,
            locality=self.config.locality,
            organization=self.config.organization,
            organizational_unit=self.config.organizational_unit,
            common_name=client_id,
        )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(client_dn.to_x509_name())
            .sign(client_key, hashes.SHA256())
        )

        client_cert = CertificateBuilder.build_client_certificate(
            csr=csr,
            issuer_cert=intermediate_cert,
            issuer_key=intermediate_key,
            validity_days=self.config.client_validity_days,
        )

        client_dir = output_dir / client_id
        client_dir.mkdir(parents=True, exist_ok=True)

        key_path = client_dir / "client.key"
        cert_path = client_dir / "client.pem"
        csr_path = client_dir / "client.csr"
        metadata_path = client_dir / "metadata.json"

        key_path.write_bytes(serialize_private_key(client_key))
        cert_path.write_bytes(serialize_certificate(client_cert))
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        metadata = extract_certificate_metadata(client_cert, client_id=client_id)
        metadata_path.write_text(json.dumps(metadata, indent=2))

        serial_number = metadata["serialNumber"]
        if not isinstance(serial_number, str):
            raise ValueError("serial number must be string")

        return ClientCertResult(
            key_path=key_path,
            cert_path=cert_path,
            csr_path=csr_path,
            metadata_path=metadata_path,
            serial_number=serial_number,
        )
