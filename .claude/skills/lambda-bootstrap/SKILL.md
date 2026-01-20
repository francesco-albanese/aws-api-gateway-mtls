# Lambda Bootstrap

Bootstrap new Lambda functions with consistent structure, tooling, and patterns.

## Trigger

Use when user asks to: bootstrap/create/add new lambda, setup lambda boilerplate, create new lambda function.

## Directory Structure

```
lambdas/<name>/
├── pyproject.toml       # uv project config
├── uv.lock              # locked dependencies
├── src/
│   └── <name>/
│       ├── __init__.py  # empty
│       └── handler.py   # Lambda entry point
└── tests/
    ├── __init__.py
    ├── conftest.py      # pytest fixtures
    └── test_handler.py  # unit tests
```

## Steps

1. Create directory: `lambdas/<name>/`
2. Create `pyproject.toml` from template (see references/pyproject-template.toml)
3. Create `src/<name>/__init__.py` (empty)
4. Create `src/<name>/handler.py` from template (see references/handler-template.py)
5. Run `cd lambdas/<name> && uv sync` to create uv.lock
6. Add ECR repo `mtls-api-<name>-lambda` to `terraform/ecr/ecr.tf`
7. Add Lambda resource to `terraform/environmental/lambda.tf`
8. Add API route to `terraform/environmental/api-gateway.tf` (if needed)

## Build

Shared Dockerfile at `lambdas/Dockerfile` uses `--build-arg LAMBDA_NAME=<name>`:

```bash
make lambda-build-<name>
```

## Patterns

### TypedDict for Events

Use TypedDict for API Gateway event typing (not Pydantic - keep lambdas lightweight):

```python
from typing import NotRequired, TypedDict

class APIGatewayProxyEventV2(TypedDict, total=False):
    requestContext: RequestContext

class APIGatewayProxyResponseV2(TypedDict):
    statusCode: int
    headers: NotRequired[dict[str, str]]
    body: NotRequired[str]
```

### LambdaContext Stub

```python
class LambdaContext:
    function_name: str
    memory_limit_in_mb: int
    invoked_function_arn: str
    aws_request_id: str
```

### mTLS Client Cert Access

```python
request_context = event.get("requestContext", {})
authentication = request_context.get("authentication", {})
client_cert = authentication.get("clientCert", {})
serial_number = client_cert.get("serialNumber")
```

## Dependencies

- No boto3 in dependencies (Lambda runtime provides it)
- Add runtime deps to `dependencies = [...]`
- Add dev deps to `[dependency-groups] dev = [...]`
