# Testing Rules

- how to run tests `uv run pytest -v`

when defining tests within a Lambda folder, you need to navigate one folder up to find the handler
DON'T DO THIS

```python
from health.handler import (
  APIGatewayProxyEventV2,
  APIGatewayProxyResponseV2,
  LambdaContext,
  handler,
)
```

DO THIS:

```python
from ..src.health.handler import (
  APIGatewayProxyEventV2,
  APIGatewayProxyResponseV2,
  LambdaContext,
  handler,
)

```

## How to run tests for CA operations

- To run tests for CA operations use `uv run --group ca --group dev pytest ca_operations/tests -v`
- To run just one specific test use `uv run --group ca --group dev pytest ca_operations/tests/test_rotate_intermediate_ca.py -v`

## How to run tests for Lambdas

Each lambda has its own `pyproject.toml` so the tests need to run from the lambda's directory:

- `cd lambdas/authorizer && uv run pytest -v`
- `cd lambdas/health && uv run pytest -v`
