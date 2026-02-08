"""Fixtures for authorizer lambda tests."""

import pytest

from src.authorizer.types import APIGatewayAuthorizerEventV2, CertMetadata, LambdaContext


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required environment variables for all tests."""
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("DYNAMODB_TABLE_NAME", "mtls-clients-metadata")


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
    """Base authorizer event without mTLS cert."""
    return {
        "type": "REQUEST",
        "routeArn": "arn:aws:execute-api:eu-west-2:123456789:abc123/$default/GET/health",
        "routeKey": "GET /health",
        "rawPath": "/health",
        "rawQueryString": "",
        "headers": {},
        "requestContext": {
            "accountId": "123456789",
            "apiId": "abc123",
            "http": {"method": "GET", "path": "/health"},
        },
    }


@pytest.fixture
def event_with_mtls_cert(base_event: APIGatewayAuthorizerEventV2) -> APIGatewayAuthorizerEventV2:
    """Event with mTLS client cert in request context."""
    base_event["requestContext"] = {
        "accountId": "123456789",
        "apiId": "abc123",
        "http": {"method": "GET", "path": "/health"},
        "authentication": {
            "clientCert": {
                "serialNumber": "ABC123DEF456",
                "subjectDN": "CN=test-client,O=TestOrg",
                "issuerDN": "CN=IntermediateCA,O=TestOrg",
                "validity": {
                    "notBefore": "2025-01-01T00:00:00Z",
                    "notAfter": "2027-01-01T00:00:00Z",
                },
            }
        },
    }
    return base_event


@pytest.fixture
def active_cert_metadata() -> CertMetadata:
    """Active certificate metadata from DynamoDB."""
    return {
        "serialNumber": "ABC123DEF456",
        "client_id": "test-client",
        "clientName": "Test Client",
        "status": "active",
        "issuedAt": "2025-01-01T00:00:00Z",
        "expiry": "2027-01-01T00:00:00Z",
    }


@pytest.fixture
def revoked_cert_metadata() -> CertMetadata:
    """Revoked certificate metadata."""
    return {
        "serialNumber": "ABC123DEF456",
        "client_id": "test-client",
        "clientName": "Test Client",
        "status": "revoked",
        "issuedAt": "2025-01-01T00:00:00Z",
        "expiry": "2027-01-01T00:00:00Z",
    }


@pytest.fixture
def expired_cert_metadata() -> CertMetadata:
    """Expired certificate metadata."""
    return {
        "serialNumber": "ABC123DEF456",
        "client_id": "test-client",
        "clientName": "Test Client",
        "status": "active",
        "issuedAt": "2023-01-01T00:00:00Z",
        "expiry": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def mismatched_cert_metadata() -> CertMetadata:
    """Metadata with client_id that doesn't match CN."""
    return {
        "serialNumber": "ABC123DEF456",
        "client_id": "different-client",
        "clientName": "Different Client",
        "status": "active",
        "issuedAt": "2025-01-01T00:00:00Z",
        "expiry": "2027-01-01T00:00:00Z",
    }
