"""Result models for CA operations."""

from dataclasses import dataclass
from pathlib import Path


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
