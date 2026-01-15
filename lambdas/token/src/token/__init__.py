"""Token exchange Lambda for mTLS API Gateway."""

from token.handler import handler

__all__ = ["handler"]
