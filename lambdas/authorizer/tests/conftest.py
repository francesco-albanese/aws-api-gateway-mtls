"""Fixtures for authorizer lambda tests."""

import pytest

from src.authorizer.types import APIGatewayAuthorizerEventV2, LambdaContext


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required environment variables for all tests."""
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "eu-west-2_testpool")
    monkeypatch.setenv("COGNITO_CLIENT_ID", "test-client-id")


@pytest.fixture
def lambda_context() -> LambdaContext:
    """Create mock Lambda context."""
    ctx = LambdaContext()
    ctx.function_name = "mtls-api-authorizer"
    ctx.memory_limit_in_mb = 128
    ctx.invoked_function_arn = "arn:aws:lambda:eu-west-2:123456789:function:mtls-api-authorizer"
    ctx.aws_request_id = "test-request-id"
    return ctx


@pytest.fixture
def base_event() -> APIGatewayAuthorizerEventV2:
    """Base authorizer event without auth headers."""
    return {
        "type": "REQUEST",
        "routeArn": "arn:aws:execute-api:eu-west-2:123456789:abc123/$default/GET/protected",
        "routeKey": "GET /protected",
        "rawPath": "/protected",
        "rawQueryString": "",
        "headers": {},
        "requestContext": {
            "accountId": "123456789",
            "apiId": "abc123",
            "http": {"method": "GET", "path": "/protected"},
        },
    }


@pytest.fixture
def event_with_mtls_cert(base_event: APIGatewayAuthorizerEventV2) -> APIGatewayAuthorizerEventV2:
    """Event with mTLS client cert in request context."""
    base_event["requestContext"] = {
        "accountId": "123456789",
        "apiId": "abc123",
        "http": {"method": "GET", "path": "/protected"},
        "authentication": {
            "clientCert": {
                "serialNumber": "ABC123DEF456",
                "subjectDN": "CN=test-client,O=TestOrg",
                "issuerDN": "CN=IntermediateCA,O=TestOrg",
                "validity": {
                    "notBefore": "2025-01-01T00:00:00Z",
                    "notAfter": "2026-01-01T00:00:00Z",
                },
            }
        },
    }
    return base_event


def event_with_bearer_token(
    event: APIGatewayAuthorizerEventV2, token: str
) -> APIGatewayAuthorizerEventV2:
    """Add Bearer token to event."""
    event["headers"] = {"authorization": f"Bearer {token}"}
    return event
