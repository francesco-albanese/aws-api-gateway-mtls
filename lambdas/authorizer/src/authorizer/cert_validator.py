"""Certificate status and identity validation."""

from datetime import UTC, datetime

from ._types import CertMetadata


def validate_cert_status(metadata: CertMetadata) -> tuple[bool, str]:
    """Validate cert is active and not expired."""
    if metadata["status"] != "active":
        return False, f"Certificate status is '{metadata['status']}'"

    now = datetime.now(UTC)
    try:
        expiry = datetime.fromisoformat(metadata["expiry"])
        if now > expiry:
            return False, "Certificate has expired"
    except ValueError:
        return False, "Invalid expiry date format"

    return True, ""


def validate_client_identity(metadata: CertMetadata, client_cn: str) -> tuple[bool, str]:
    """Validate that cert CN matches DynamoDB client_id."""
    if metadata["client_id"] != client_cn:
        return False, f"CN '{client_cn}' does not match client_id '{metadata['client_id']}'"
    return True, ""
