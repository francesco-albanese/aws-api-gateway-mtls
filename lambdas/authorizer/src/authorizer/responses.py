"""Response builders for authorizer Lambda."""

from authorizer.types import AuthorizerResponse


def deny_response() -> AuthorizerResponse:
    """Return deny response."""
    return {"isAuthorized": False}


def allow_response(serial_number: str, client_id: str, scopes: list[str]) -> AuthorizerResponse:
    """Return allow response with context."""
    return {
        "isAuthorized": True,
        "context": {
            "serialNumber": serial_number,
            "clientId": client_id,
            "scopes": ",".join(scopes),
        },
    }
