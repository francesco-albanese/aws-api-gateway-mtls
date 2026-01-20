"""Tests for health lambda handler."""

import json
from typing import Any

import pytest

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


class TestHandlerWithValidMTLSCert:
    """Test handler with full mTLS certificate metadata."""

    def test_returns_200_status(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler returns 200 status code."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        assert response["statusCode"] == 200

    def test_extracts_client_cn(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler extracts CN from subjectDN."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] == "test-client"

    def test_includes_serial_number(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler includes certificate serial number."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["serialNumber"] == "1234567890ABCDEF"

    def test_includes_validity(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler includes certificate validity dates."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["validity"]["notBefore"] == "Jan 15 00:00:00 2026 GMT"
        assert body["mtls"]["validity"]["notAfter"] == "Jan 15 00:00:00 2027 GMT"

    def test_mtls_enabled_true(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler sets mtls.enabled to true when cert present."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is True


class TestHandlerMissingClientCert:
    """Test handler when mTLS client certificate is missing."""

    def test_mtls_enabled_false_no_cert(
        self,
        event_without_client_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler sets mtls.enabled to false when no clientCert."""
        response = handler(event_without_client_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["enabled"] is False

    def test_client_cn_none_no_cert(
        self,
        event_without_client_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler sets clientCN to None when no clientCert."""
        response = handler(event_without_client_cert, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] is None

    def test_empty_request_context(
        self,
        event_empty_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler handles empty request context gracefully."""
        response = handler(event_empty_request_context, mock_context)
        body = parse_response_body(response)
        assert body["status"] == "healthy"
        assert body["mtls"]["enabled"] is False

    def test_no_request_context(
        self,
        event_no_request_context: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler handles missing request context gracefully."""
        response = handler(event_no_request_context, mock_context)
        body = parse_response_body(response)
        assert body["status"] == "healthy"
        assert body["mtls"]["enabled"] is False


class TestDNParsingEdgeCases:
    """Test DN parsing edge cases."""

    @pytest.mark.parametrize(
        ("subject_dn", "expected_cn"),
        [
            ("CN=first-cn,O=Org,C=US", "first-cn"),  # CN at start
            ("O=Org,C=US,CN=last-cn", "last-cn"),  # CN at end
            ("O=Org,CN=middle-cn,C=US", "middle-cn"),  # CN in middle
            ("CN=has-dash,O=Org", "has-dash"),  # dash in CN
            ("CN=has_underscore,O=Org", "has_underscore"),  # underscore in CN
            ("CN=has.dot,O=Org", "has.dot"),  # dot in CN
            ("CN=MixedCase,O=Org", "MixedCase"),  # mixed case
            ("CN=123numeric,O=Org", "123numeric"),  # numeric start
        ],
    )
    def test_cn_extraction_variants(
        self,
        subject_dn: str,
        expected_cn: str,
        mock_context: LambdaContext,
    ) -> None:
        """Handler extracts CN correctly from various DN formats."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authentication": {
                    "clientCert": {
                        "subjectDN": subject_dn,
                        "serialNumber": "ABCD1234",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] == expected_cn

    def test_empty_subject_dn(self, mock_context: LambdaContext) -> None:
        """Handler handles empty subjectDN."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authentication": {
                    "clientCert": {
                        "subjectDN": "",
                        "serialNumber": "ABCD1234",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["clientCN"] is None


class TestMissingValidityFields:
    """Test handler with missing validity fields."""

    def test_cert_without_validity(self, mock_context: LambdaContext) -> None:
        """Handler handles cert without validity field."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authentication": {
                    "clientCert": {
                        "subjectDN": "CN=test-client,O=Org",
                        "serialNumber": "ABCD1234",
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["validity"] == {}
        assert body["mtls"]["enabled"] is True

    def test_cert_with_partial_validity(self, mock_context: LambdaContext) -> None:
        """Handler handles cert with partial validity (only notBefore)."""
        event: APIGatewayProxyEventV2 = {
            "requestContext": {
                "authentication": {
                    "clientCert": {
                        "subjectDN": "CN=test-client,O=Org",
                        "serialNumber": "ABCD1234",
                        "validity": {"notBefore": "Jan 15 00:00:00 2026 GMT"},  # type: ignore[typeddict-item]
                    }
                }
            }
        }
        response = handler(event, mock_context)
        body = parse_response_body(response)
        assert body["mtls"]["validity"]["notBefore"] == "Jan 15 00:00:00 2026 GMT"
        assert "notAfter" not in body["mtls"]["validity"]


class TestResponseJSONStructure:
    """Verify exact response format."""

    def test_content_type_header(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Response has correct Content-Type header."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        assert response.get("headers", {}).get("Content-Type") == "application/json"

    def test_body_is_valid_json(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Response body is valid JSON."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)  # raises if invalid JSON
        assert isinstance(body, dict)

    def test_response_structure(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Response has expected top-level structure."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        assert "status" in body
        assert "mtls" in body
        assert body["status"] == "healthy"

    def test_mtls_structure(
        self,
        event_with_valid_mtls_cert: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Response mtls object has expected fields."""
        response = handler(event_with_valid_mtls_cert, mock_context)
        body = parse_response_body(response)
        mtls = body["mtls"]
        assert "enabled" in mtls
        assert "clientCN" in mtls
        assert "serialNumber" in mtls
        assert "validity" in mtls
