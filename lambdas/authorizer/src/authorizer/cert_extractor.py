"""Certificate extraction from API Gateway mTLS context."""

from authorizer.types import APIGatewayAuthorizerEventV2


def extract_serial_number(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract certificate serial number from mTLS context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")


def extract_client_cn(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract client CN from certificate subjectDN."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    subject_dn = client_cert.get("subjectDN", "")
    if not subject_dn:
        return None
    return subject_dn.split("CN=")[-1].split(",")[0]


def extract_validity(event: APIGatewayAuthorizerEventV2) -> tuple[str, str]:
    """Extract certificate validity dates from mTLS context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    validity = client_cert.get("validity", {})
    return validity.get("notBefore", ""), validity.get("notAfter", "")
