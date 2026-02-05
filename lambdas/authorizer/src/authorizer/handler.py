"""Custom authorizer Lambda - validates Cognito JWT and mTLS cert context."""

import os

from authorizer.event_parser import extract_bearer_token, extract_serial_number
from authorizer.jwt_validator import validate_jwt
from authorizer.responses import allow_response, deny_response
from authorizer.types import APIGatewayAuthorizerEventV2, AuthorizerResponse, LambdaContext


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
    region = os.environ.get("AWS_REGION", "eu-west-2")
    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
    client_id = os.environ.get("COGNITO_CLIENT_ID", "")

    if not user_pool_id or not client_id:
        return deny_response()

    # Extract token
    token = extract_bearer_token(event)
    if not token:
        return deny_response()

    # Extract mTLS cert serial (optional validation)
    serial_number = extract_serial_number(event)

    # Validate JWT
    claims = validate_jwt(token, region, user_pool_id, client_id)
    if not claims:
        return deny_response()

    # Extract scopes from token
    scope_str = claims.get("scope", "")
    scopes = scope_str.split() if isinstance(scope_str, str) else []

    # Return allow with context
    return allow_response(
        serial_number=serial_number or "",
        client_id=str(claims.get("client_id", "")),
        scopes=scopes,
    )
