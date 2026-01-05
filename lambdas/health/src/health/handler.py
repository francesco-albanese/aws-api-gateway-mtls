"""Health check Lambda handler for mTLS API."""

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
    """Return health status with mTLS client cert info."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})

    subject_dn = client_cert.get("subjectDN", "")
    client_cn = subject_dn.split("CN=")[-1].split(",")[0] if subject_dn else None

    response_body = {
        "status": "healthy",
        "mtls": {
            "enabled": bool(client_cert),
            "clientCN": client_cn,
            "serialNumber": client_cert.get("serialNumber"),
            "validity": client_cert.get("validity", {}),
        },
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(response_body),
    }
