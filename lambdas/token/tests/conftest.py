"""Test fixtures for token lambda tests."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from src.token.types import (
    APIGatewayProxyEventV2,
    CertMetadata,
    CognitoTokenResponse,
    LambdaContext,
)


class MockLambdaContext(LambdaContext):
    """Mock Lambda context for testing."""

    function_name = "mtls-token-lambda"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:mtls-token-lambda"
    aws_request_id = "test-request-id-12345"


@pytest.fixture
def mock_context() -> LambdaContext:
    """Provide mock Lambda context."""
    return MockLambdaContext()


@pytest.fixture
def event_with_serial_number() -> APIGatewayProxyEventV2:
    """Event with mTLS client certificate serial number."""
    return {
        "requestContext": {
            "authentication": {
                "clientCert": {
                    "clientCertPem": "-----BEGIN CERTIFICATE-----\nMIIC...",
                    "subjectDN": "CN=test-client,O=TestOrg,C=US",
                    "issuerDN": "CN=Intermediate CA,O=TestOrg,C=US",
                    "serialNumber": "1234567890ABCDEF",
                    "validity": {
                        "notBefore": "Jan 15 00:00:00 2026 GMT",
                        "notAfter": "Jan 15 00:00:00 2027 GMT",
                    },
                }
            }
        }
    }


@pytest.fixture
def event_without_serial_number() -> APIGatewayProxyEventV2:
    """Event without mTLS client certificate."""
    return {"requestContext": {"authentication": {}}}


@pytest.fixture
def event_empty() -> APIGatewayProxyEventV2:
    """Empty event."""
    return {}


@pytest.fixture
def active_cert_metadata() -> CertMetadata:
    """Active certificate metadata from DynamoDB."""
    future_expiry = (datetime.now(UTC) + timedelta(days=365)).isoformat()
    return {
        "serialNumber": "1234567890ABCDEF",
        "client_id": "cognito-client-123",
        "clientName": "test-client",
        "status": "active",
        "issuedAt": "2026-01-15T00:00:00+00:00",
        "expiry": future_expiry,
    }


@pytest.fixture
def revoked_cert_metadata() -> CertMetadata:
    """Revoked certificate metadata from DynamoDB."""
    future_expiry = (datetime.now(UTC) + timedelta(days=365)).isoformat()
    return {
        "serialNumber": "1234567890ABCDEF",
        "client_id": "cognito-client-123",
        "clientName": "test-client",
        "status": "revoked",
        "issuedAt": "2026-01-15T00:00:00+00:00",
        "expiry": future_expiry,
    }


@pytest.fixture
def expired_cert_metadata() -> CertMetadata:
    """Expired certificate metadata from DynamoDB."""
    past_expiry = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    return {
        "serialNumber": "1234567890ABCDEF",
        "client_id": "cognito-client-123",
        "clientName": "test-client",
        "status": "active",
        "issuedAt": "2025-01-15T00:00:00+00:00",
        "expiry": past_expiry,
    }


@pytest.fixture
def mock_env_vars() -> dict[str, str]:
    """Mock environment variables for Cognito config."""
    return {
        "DYNAMODB_TABLE_NAME": "mtls-clients-metadata",
        "COGNITO_DOMAIN": "test-domain.auth.us-east-1.amazoncognito.com",
        "COGNITO_CLIENT_ID": "test-client-id",
        "COGNITO_CLIENT_SECRET": "test-client-secret",
    }


@pytest.fixture
def mock_cognito_token_response() -> CognitoTokenResponse:
    """Mock Cognito token endpoint response."""
    return {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
        "token_type": "Bearer",
        "expires_in": 3600,
    }


@pytest.fixture
def mock_dynamodb_client():
    """Create mock DynamoDB client."""
    return MagicMock()


@pytest.fixture
def patch_dynamodb(mock_dynamodb_client: MagicMock):
    """Patch get_dynamodb_client to return mock."""
    with patch(
        "src.token.cert_metadata.get_dynamodb_client",
        return_value=mock_dynamodb_client,
    ) as p:
        yield p


@pytest.fixture
def patch_cognito_exchange():
    """Patch exchange_for_cognito_token."""
    with patch("src.token.cognito_exchange.exchange_for_cognito_token") as p:
        yield p
