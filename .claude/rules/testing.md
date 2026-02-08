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
