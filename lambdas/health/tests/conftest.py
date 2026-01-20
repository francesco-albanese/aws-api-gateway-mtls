"""Test fixtures for health lambda tests."""

import pytest

from src.health.handler import APIGatewayProxyEventV2, LambdaContext


class MockLambdaContext(LambdaContext):
    """Mock Lambda context for testing."""

    function_name = "mtls-health-lambda"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:mtls-health-lambda"
    aws_request_id = "test-request-id-12345"


@pytest.fixture
def mock_context() -> LambdaContext:
    """Provide mock Lambda context."""
    return MockLambdaContext()


@pytest.fixture
def event_with_valid_mtls_cert() -> APIGatewayProxyEventV2:
    """Event with full mTLS client certificate metadata."""
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
def event_without_client_cert() -> APIGatewayProxyEventV2:
    """Event without mTLS client certificate (mtls disabled or missing)."""
    return {"requestContext": {"authentication": {}}}


@pytest.fixture
def event_empty_request_context() -> APIGatewayProxyEventV2:
    """Event with empty request context."""
    return {"requestContext": {}}


@pytest.fixture
def event_no_request_context() -> APIGatewayProxyEventV2:
    """Event without request context at all."""
    return {}
