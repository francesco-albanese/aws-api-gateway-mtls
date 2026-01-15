"""CA configuration dataclasses."""

from dataclasses import dataclass

from cryptography import x509
from cryptography.x509 import oid


@dataclass
class CAConfig:
    """CA configuration with no AWS dependencies."""

    country: str = "GB"
    state: str = "London"
    locality: str = "London"
    organization: str = "Francesco Albanese"
    organizational_unit: str = "Engineering"
    root_validity_years: int = 10
    intermediate_validity_years: int = 5
    client_validity_days: int = 395
    key_size: int = 4096


@dataclass
class DistinguishedName:
    """X.509 Subject Distinguished Name."""

    country: str
    state: str
    locality: str
    organization: str
    organizational_unit: str
    common_name: str

    def to_x509_name(self) -> x509.Name:
        """Convert to cryptography x509.Name for certificate generation."""
        return x509.Name(
            [
                x509.NameAttribute(oid.NameOID.COUNTRY_NAME, self.country),
                x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, self.state),
                x509.NameAttribute(oid.NameOID.LOCALITY_NAME, self.locality),
                x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, self.organization),
                x509.NameAttribute(oid.NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
                x509.NameAttribute(oid.NameOID.COMMON_NAME, self.common_name),
            ]
        )
