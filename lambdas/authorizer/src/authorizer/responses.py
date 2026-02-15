"""Response builders for authorizer Lambda."""

from ._types import AuthorizerResponse


def deny_response() -> AuthorizerResponse:
    """Return deny response."""
    return {"isAuthorized": False}


def allow_response(
    serial_number: str,
    client_cn: str,
    client_id: str,
    validity_not_before: str,
    validity_not_after: str,
) -> AuthorizerResponse:
    """Return allow response with mTLS context."""
    return {
        "isAuthorized": True,
        "context": {
            "serialNumber": serial_number,
            "clientCN": client_cn,
            "clientId": client_id,
            "validityNotBefore": validity_not_before,
            "validityNotAfter": validity_not_after,
        },
    }
