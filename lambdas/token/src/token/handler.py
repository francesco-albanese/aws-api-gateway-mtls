"""Token exchange Lambda handler - exchanges mTLS client cert for JWT."""

import json
from typing import NotRequired, TypedDict


class CertValidity(TypedDict):
    notBefore: str
    notAfter: str


class ClientCert(TypedDict, total=False):
    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: CertValidity


class Authentication(TypedDict, total=False):
    clientCert: ClientCert


class RequestContext(TypedDict, total=False):
    authentication: Authentication


class APIGatewayProxyEventV2(TypedDict, total=False):
    """API Gateway HTTP API v2 event (partial, mTLS-relevant fields)."""

    requestContext: RequestContext


class APIGatewayProxyResponseV2(TypedDict):
    """API Gateway HTTP API v2 response."""

    statusCode: int
    headers: NotRequired[dict[str, str]]
    body: NotRequired[str]


class LambdaContext:
    """AWS Lambda context object stub for typing."""

    function_name: str
    memory_limit_in_mb: int
    invoked_function_arn: str
    aws_request_id: str


def _extract_serial_number(event: APIGatewayProxyEventV2) -> str | None:
    """Extract certificate serial number from mTLS context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")


def _json_response(status_code: int, body: dict) -> APIGatewayProxyResponseV2:
    """Build JSON API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event: APIGatewayProxyEventV2, context: LambdaContext) -> APIGatewayProxyResponseV2:
    """Exchange mTLS client certificate for JWT access token.

    Flow:
    1. Extract serialNumber from mTLS client cert
    2. Lookup cert in DynamoDB (validate not revoked/expired)
    3. Exchange for Cognito JWT via client_credentials grant
    4. Return access_token
    """
    serial_number = _extract_serial_number(event)

    if not serial_number:
        return _json_response(
            401,
            {"error": "unauthorized", "message": "Missing client certificate"},
        )

    # TODO: PRD-005 - DynamoDB lookup by serialNumber
    # TODO: PRD-005 - Validate cert status (active, not revoked)
    # TODO: PRD-005 - Cognito client_credentials token exchange

    # Placeholder: return serial number to confirm extraction works
    return _json_response(
        501,
        {
            "error": "not_implemented",
            "message": "Token exchange not yet implemented",
            "serialNumber": serial_number,
        },
    )
