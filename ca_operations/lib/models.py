"""Result models for CA operations."""

from dataclasses import dataclass
from pathlib import Path
from typing import NotRequired, TypedDict


class CertificateMetadata(TypedDict):
    """Certificate metadata from DynamoDB."""

    serialNumber: str
    client_id: NotRequired[str]
    clientName: str
    status: str
    issuedAt: str
    expiry: str
    notBefore: str
    ttl: int


@dataclass
class BootstrapResult:
    """Result from CA bootstrap operation.

    Contains file paths and serial numbers for Root and Intermediate CA artifacts.
    """

    root_key_path: Path
    root_cert_path: Path
    root_serial: str
    intermediate_key_path: Path
    intermediate_cert_path: Path
    intermediate_csr_path: Path
    intermediate_serial: str


@dataclass
class ClientCertResult:
    """Result from client certificate provisioning.

    Contains file paths and serial number for client certificate artifacts.
    """

    key_path: Path
    cert_path: Path
    csr_path: Path
    metadata_path: Path
    serial_number: str


@dataclass
class RotationResult:
    """Result from intermediate CA rotation.

    Contains counts and details of rotation operation.
    """

    reissued_count: int
    revoked_count: int
    failed_count: int
    new_intermediate_serial: str
    truststore_version_id: str
    reissued_serials: list[str]
    failed_client_ids: list[str]
