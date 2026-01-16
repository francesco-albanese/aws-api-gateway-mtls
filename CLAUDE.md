## Project Overview

AWS API Gateway HTTP regional endpoint with mTLS enforcement. Uses certificate chain mechanism (Root CA → Intermediate CA → Client certs) with S3 truststore, custom domains, ACM certs, Cognito client_credentials flow, and DynamoDB for certificate metadata validation.

## Build System

Makefile-based build system with modular makefiles in [makefiles/](makefiles/).

## Terraform Architecture

Multi-stack pattern with environment separation:

**Environmental Stack** (`terraform/environmental/`):

- Contains: API Gateway, custom domain, ACM cert, Lambda functions, Cognito, DynamoDB, Route53

**Certificate bootstrap Stack** (`terraform/certificate-bootstrap/`):

- Contains: S3 truststore, CA certs and private keys stored as SSM parameter store

**Client provisioning Stack** (`terraform/client-provisioning/`):

- Contains: dynamodb table items such as serialNumber of clients certs, clientName, client_id, clients private key and cert stored in SSM parameter store

**ECR Stack** (`terraform/ecr/`):

- Contains: ECR repositories for Lambda container images

## Certificate Authority Structure

**3-tier PKI chain:**

1. Root CA (self-signed, 10yr) → 2. Intermediate CA (signed by Root, 5yr) → 3. Client certs (signed by Intermediate, 1yr)

**Storage:**

- Truststore: S3 bucket with chain bundle (IntermediateCA.pem + RootCA.pem)

## Test rules

- when defining tests within a Lambda folder, you need to navigate one folder up to find the handler
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

  ## Lambda rules

- When creating a Lambda, if the lambda needs to call other functions with a specific functionality, extract those functions outside the `handler.py` giving it a meaningful name.
- Example: extract metadata certs from Dynamodb, create `extract_certs.py` and import the needed function into `handler.py` for consumption.
- Make sure to follow single responsibility principle, keep the code modular

# Lint rules

- uv run ruff format --check must be ran individually per lambda
- `.pre-commit-config.yaml` might not have the correct hook if a lambda has just been added, must be updated
