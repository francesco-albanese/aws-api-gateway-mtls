"""Type definitions for authorizer Lambda."""

from typing import NotRequired, TypedDict


class CertMetadata(TypedDict):
    """DynamoDB cert metadata item."""

    serialNumber: str
    client_id: str
    clientName: str
    status: str
    issuedAt: str
    expiry: str


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
    accountId: str
    apiId: str
    http: dict[str, str]


class APIGatewayAuthorizerEventV2(TypedDict, total=False):
    """API Gateway HTTP API v2 authorizer event (REQUEST type)."""

    type: str
    routeArn: str
    identitySource: list[str]
    routeKey: str
    rawPath: str
    rawQueryString: str
    headers: dict[str, str]
    requestContext: RequestContext


class AuthorizerResponse(TypedDict):
    """Lambda authorizer simple response for HTTP API."""

    isAuthorized: bool
    context: NotRequired[dict[str, str | int | bool]]


class LambdaContext:
    """AWS Lambda context object stub for typing."""

    function_name: str
    memory_limit_in_mb: int
    invoked_function_arn: str
    aws_request_id: str
