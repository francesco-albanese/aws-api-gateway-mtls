"""{{description}}."""

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


def handler(event: APIGatewayProxyEventV2, context: LambdaContext) -> APIGatewayProxyResponseV2:
    """Handle API Gateway request."""
    # Extract mTLS client cert if present
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    serial_number = client_cert.get("serialNumber")

    # TODO: Implement handler logic

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "OK", "serialNumber": serial_number}),
    }
