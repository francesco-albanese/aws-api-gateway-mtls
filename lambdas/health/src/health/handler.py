"""Health check Lambda handler for mTLS API."""

import json
from typing import NotRequired, TypedDict


class LambdaAuthorizerContext(TypedDict, total=False):
    """Context values set by the mTLS authorizer Lambda."""

    clientCN: str
    serialNumber: str
    clientId: str
    validityNotBefore: str
    validityNotAfter: str


AuthorizerContext = TypedDict("AuthorizerContext", {"lambda": LambdaAuthorizerContext}, total=False)


class RequestContext(TypedDict, total=False):
    """Request context from API Gateway."""

    authorizer: AuthorizerContext


class APIGatewayProxyEventV2(TypedDict, total=False):
    """API Gateway HTTP API v2 event (partial, authorizer-relevant fields)."""

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
    """Return health status with mTLS client cert info from authorizer context."""
    request_context = event.get("requestContext", {})
    authorizer = request_context.get("authorizer", {})
    # API Gateway nests lambda authorizer context under "lambda" key
    auth_context = authorizer.get("lambda", {})

    client_cn = auth_context.get("clientCN") or None
    serial_number = auth_context.get("serialNumber") or None
    validity = {}
    not_before = auth_context.get("validityNotBefore", "")
    not_after = auth_context.get("validityNotAfter", "")
    if not_before:
        validity["notBefore"] = not_before
    if not_after:
        validity["notAfter"] = not_after

    response_body = {
        "status": "healthy",
        "mtls": {
            "enabled": bool(serial_number),
            "clientCN": client_cn,
            "serialNumber": serial_number,
            "validity": validity,
        },
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(response_body),
    }
