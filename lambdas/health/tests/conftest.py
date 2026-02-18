"""Test fixtures for health lambda tests."""

import pytest

from src.health.handler import APIGatewayProxyEventV2, LambdaContext


class MockLambdaContext(LambdaContext):
    """Mock Lambda context for testing."""

    function_name = "mtls-health-lambda"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:eu-west-2:123456789012:function:mtls-health-lambda"
    aws_request_id = "test-request-id-12345"


@pytest.fixture
def mock_context() -> LambdaContext:
    """Provide mock Lambda context."""
    return MockLambdaContext()


@pytest.fixture
def event_with_authorizer_context() -> APIGatewayProxyEventV2:
    """Event with full authorizer context from mTLS authorizer."""
    return {
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "serialNumber": "1311768467294899695",
                    "clientCN": "test-client",
                    "clientId": "test-client",
                    "validityNotBefore": "2025-01-01T00:00:00Z",
                    "validityNotAfter": "2027-01-01T00:00:00Z",
                }
            }
        }
    }


@pytest.fixture
def event_without_authorizer_context() -> APIGatewayProxyEventV2:
    """Event without authorizer context."""
    return {"requestContext": {"authorizer": {}}}


@pytest.fixture
def event_empty_request_context() -> APIGatewayProxyEventV2:
    """Event with empty request context."""
    return {"requestContext": {}}


@pytest.fixture
def event_no_request_context() -> APIGatewayProxyEventV2:
    """Event without request context at all."""
    return {}
