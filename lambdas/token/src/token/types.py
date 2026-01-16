"""Type definitions for token lambda."""

from typing import NotRequired, TypedDict


class CertValidity(TypedDict):
    """Certificate validity period from mTLS context."""

    notBefore: str
    notAfter: str


class ClientCert(TypedDict, total=False):
    """Client certificate metadata from mTLS context."""

    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: CertValidity


class Authentication(TypedDict, total=False):
    """Authentication context from API Gateway."""

    clientCert: ClientCert


class RequestContext(TypedDict, total=False):
    """Request context from API Gateway."""

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


class CertMetadata(TypedDict):
    """DynamoDB cert metadata item."""

    serialNumber: str
    client_id: str
    clientName: str
    status: str
    issuedAt: str
    expiry: str


class CognitoTokenResponse(TypedDict):
    """Cognito token endpoint response."""

    access_token: str
    token_type: str
    expires_in: int
