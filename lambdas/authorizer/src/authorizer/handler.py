"""Custom authorizer Lambda - validates Cognito JWT and mTLS cert context."""

import os
from typing import NotRequired, TypedDict

import jwt
from jwt import PyJWKClient


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


class IAMPolicyStatement(TypedDict):
    Action: str
    Effect: str
    Resource: str


class IAMPolicyDocument(TypedDict):
    Version: str
    Statement: list[IAMPolicyStatement]


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


# Global JWKS client (cached across invocations)
_jwks_client: PyJWKClient | None = None


def _get_jwks_client(region: str, user_pool_id: str) -> PyJWKClient:
    """Get cached JWKS client for Cognito user pool."""
    global _jwks_client
    if _jwks_client is None:
        jwks_url = (
            f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
        )
        _jwks_client = PyJWKClient(jwks_url)
    return _jwks_client


def _extract_bearer_token(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract Bearer token from Authorization header."""
    headers = event.get("headers", {})
    auth_header = headers.get("authorization", headers.get("Authorization", ""))
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def _extract_serial_number(event: APIGatewayAuthorizerEventV2) -> str | None:
    """Extract mTLS certificate serial number from request context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")


def _validate_jwt(
    token: str, region: str, user_pool_id: str, client_id: str
) -> dict[str, str | int | list[str]] | None:
    """Validate Cognito JWT and return claims if valid."""
    try:
        jwks_client = _get_jwks_client(region, user_pool_id)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",
            options={
                "verify_aud": False,  # client_credentials tokens use 'client_id' not 'aud'
            },
        )

        # Verify client_id for M2M tokens
        if claims.get("client_id") != client_id:
            return None

        return claims
    except jwt.exceptions.PyJWTError:
        return None


def _deny_response() -> AuthorizerResponse:
    """Return deny response."""
    return {"isAuthorized": False}


def _allow_response(serial_number: str, client_id: str, scopes: list[str]) -> AuthorizerResponse:
    """Return allow response with context."""
    return {
        "isAuthorized": True,
        "context": {
            "serialNumber": serial_number,
            "clientId": client_id,
            "scopes": ",".join(scopes),
        },
    }


def handler(event: APIGatewayAuthorizerEventV2, context: LambdaContext) -> AuthorizerResponse:
    """Validate JWT and mTLS cert, return authorization decision.

    Flow:
    1. Extract Bearer token from Authorization header
    2. Extract mTLS cert serialNumber from request context
    3. Validate JWT signature and claims
    4. (Future) Verify serialNumber matches token's client context
    5. Return allow/deny decision
    """
    # Get config from environment
    region = os.environ.get("AWS_REGION", "us-east-1")
    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
    client_id = os.environ.get("COGNITO_CLIENT_ID", "")

    if not user_pool_id or not client_id:
        return _deny_response()

    # Extract token
    token = _extract_bearer_token(event)
    if not token:
        return _deny_response()

    # Extract mTLS cert serial (optional validation)
    serial_number = _extract_serial_number(event)

    # Validate JWT
    claims = _validate_jwt(token, region, user_pool_id, client_id)
    if not claims:
        return _deny_response()

    # Extract scopes from token
    scope_str = claims.get("scope", "")
    scopes = scope_str.split() if isinstance(scope_str, str) else []

    # Return allow with context
    return _allow_response(
        serial_number=serial_number or "",
        client_id=str(claims.get("client_id", "")),
        scopes=scopes,
    )
