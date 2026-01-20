"""Certificate status validation."""

from datetime import UTC, datetime

from .types import CertMetadata


def validate_cert_status(metadata: CertMetadata) -> tuple[bool, str]:
    """Validate cert is active and not expired.

    Args:
        metadata: Certificate metadata from DynamoDB

    Returns:
        Tuple of (is_valid, reason_if_invalid)
    """
    if metadata["status"] != "active":
        return False, f"Certificate status is '{metadata['status']}'"

    now = datetime.now(UTC)
    try:
        expiry = datetime.fromisoformat(metadata["expiry"].replace("Z", "+00:00"))
        if now > expiry:
            return False, "Certificate has expired"
    except ValueError:
        return False, "Invalid expiry date format"

    return True, ""
