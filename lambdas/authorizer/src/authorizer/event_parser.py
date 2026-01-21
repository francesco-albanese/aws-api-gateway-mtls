"""Event parsing utilities for API Gateway authorizer events."""

from authorizer.types import APIGatewayAuthorizerEventV2


def extract_bearer_token(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract Bearer token from Authorization header."""
    headers = event.get("headers", {})
    auth_header = headers.get("authorization", headers.get("Authorization", ""))
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def extract_serial_number(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract mTLS certificate serial number from request context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")
