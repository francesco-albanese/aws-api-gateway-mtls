"""Custom authorizer Lambda for mTLS cert validation."""

try:
    from _types import (  # type: ignore[reportMissingImports]
        APIGatewayAuthorizerEventV2,
        AuthorizerResponse,
        LambdaContext,
    )
    from handler import handler  # type: ignore[reportMissingImports]
except ImportError:
    from ._types import (
        APIGatewayAuthorizerEventV2,
        AuthorizerResponse,
        LambdaContext,
    )
    from .handler import handler

__all__ = [
    "handler",
    "APIGatewayAuthorizerEventV2",
    "AuthorizerResponse",
    "LambdaContext",
]
