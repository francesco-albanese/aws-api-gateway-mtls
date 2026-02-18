"""Tests for health lambda handler."""

import json
from typing import Any

from src.health.handler import (
    APIGatewayProxyEventV2,
    APIGatewayProxyResponseV2,
    LambdaContext,
    handler,
)


def parse_response_body(response: APIGatewayProxyResponseV2) -> dict[str, Any]:
    """Parse response body, asserting it exists."""
    body = response.get("body")
    assert body is not None, "Response body should not be None"
    return json.loads(body)


class TestHandlerWithAuthorizerContext:
    """Test handler with authorizer context from mTLS authorizer."""

    def test_returns_200_status(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        assert response["statusCode"] == 200

    def test_extracts_client_cn(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] == "test-client"

    def test_includes_serial_number(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["serialNumber"] == "1311768467294899695"

    def test_includes_validity(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["validity"]["notBefore"] == "2025-01-01T00:00:00Z"
        assert body["mtls"]["validity"]["notAfter"] == "2027-01-01T00:00:00Z"

    def test_mtls_enabled_true(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is True


class TestHandlerMissingAuthorizerContext:
    """Test handler when authorizer context is missing."""

    def test_mtls_enabled_false_no_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is False

    def test_client_cn_none_no_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] is None

    def test_empty_request_context(
        self,
        event_empty_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_empty_request_context, mock_context)
        body = parse_response_body(response)
        assert body["status"] == "healthy"
        assert body["mtls"]["enabled"] is False

    def test_no_request_context(
        self,
        event_no_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_no_request_context, mock_context)
        body = parse_response_body(response)
        assert body["status"] == "healthy"
        assert body["mtls"]["enabled"] is False

    def test_serial_number_none_no_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["serialNumber"] is None

    def test_empty_validity_no_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["validity"] == {}


class TestResponseStructure:
    """Verify exact response format."""

    def test_content_type_header(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        assert response.get("headers", {}).get("Content-Type") == "application/json"

    def test_body_is_valid_json(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert isinstance(body, dict)

    def test_response_has_status_and_mtls(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert "status" in body
        assert "mtls" in body
        assert body["status"] == "healthy"

    def test_mtls_fields(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        mtls = body["mtls"]
        assert "enabled" in mtls
        assert "clientCN" in mtls
        assert "serialNumber" in mtls
        assert "validity" in mtls


class TestPartialAuthorizerContext:
    """Tests with partial authorizer context fields."""

    def test_serial_number_only(self, mock_context: LambdaContext) -> None:
        """Event with serialNumber but no clientCN."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authorizer": {
                    "lambda": {
                        "serialNumber": "1311768467294899695",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is True
        assert body["mtls"]["serialNumber"] == "1311768467294899695"
        assert body["mtls"]["clientCN"] is None

    def test_client_cn_only(self, mock_context: LambdaContext) -> None:
        """Event with clientCN but no serialNumber."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authorizer": {
                    "lambda": {
                        "clientCN": "test-client",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is False
        assert body["mtls"]["clientCN"] == "test-client"
        assert body["mtls"]["serialNumber"] is None

    def test_validity_only(self, mock_context: LambdaContext) -> None:
        """Event with only validity fields."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authorizer": {
                    "lambda": {
                        "validityNotBefore": "2025-01-01T00:00:00Z",
                        "validityNotAfter": "2027-01-01T00:00:00Z",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is False
        assert body["mtls"]["validity"]["notBefore"] == "2025-01-01T00:00:00Z"
        assert body["mtls"]["validity"]["notAfter"] == "2027-01-01T00:00:00Z"


class TestCompactJSON:
    """Verify body is compact JSON (no pretty printing)."""

    def test_body_is_compact_json(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body_str = response.get("body", "")
        assert "\n" not in body_str
        assert "  " not in body_str

    def test_body_is_compact_json_no_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body_str = response.get("body", "")
        assert "\n" not in body_str
        assert "  " not in body_str


class TestResponseBodyStructure:
    """Verify all expected keys are present across scenarios."""

    EXPECTED_TOP_KEYS = {"status", "mtls"}
    EXPECTED_MTLS_KEYS = {"enabled", "clientCN", "serialNumber", "validity"}

    def test_all_keys_with_full_context(
        self,
        event_with_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_with_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert set(body.keys()) == self.EXPECTED_TOP_KEYS
        assert set(body["mtls"].keys()) == self.EXPECTED_MTLS_KEYS

    def test_all_keys_without_context(
        self,
        event_without_authorizer_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_without_authorizer_context, mock_context)
        body = parse_response_body(response)
        assert set(body.keys()) == self.EXPECTED_TOP_KEYS
        assert set(body["mtls"].keys()) == self.EXPECTED_MTLS_KEYS

    def test_all_keys_empty_request_context(
        self,
        event_empty_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_empty_request_context, mock_context)
        body = parse_response_body(response)
        assert set(body.keys()) == self.EXPECTED_TOP_KEYS
        assert set(body["mtls"].keys()) == self.EXPECTED_MTLS_KEYS

    def test_all_keys_no_request_context(
        self,
        event_no_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        response = handler(event_no_request_context, mock_context)
        body = parse_response_body(response)
        assert set(body.keys()) == self.EXPECTED_TOP_KEYS
        assert set(body["mtls"].keys()) == self.EXPECTED_MTLS_KEYS
