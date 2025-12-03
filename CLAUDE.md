# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AWS API Gateway HTTP regional endpoint with mTLS enforcement. Uses certificate chain mechanism (Root CA → Intermediate CA → Client certs) with S3 truststore, custom domains, ACM certs, Cognito client_credentials flow, and DynamoDB for certificate metadata validation.

## Build System

Makefile-based build system with modular makefiles in [makefiles/](makefiles/).

### Terraform Commands

```bash
# Setup (macOS: brew install terraform preferred)
make tf-setup              # Install terraform tooling
make tf-configure          # Set terraform version via tfenv

# Stack operations (pattern: make <stack>-<action>)
make environmental-init    # Initialize with state backend
make environmental-plan    # Show execution plan
make environmental-apply   # Apply changes
make environmental-destroy # Destroy resources
make environmental-clean   # Remove .terraform/ and lock
make environmental-lint    # Run tflint

# All stacks at once
make init                  # Init all stacks
make plan                  # Plan all stacks
make clean                 # Clean all stacks

# Override defaults
make environmental-plan ACCOUNT=staging AWS_PROFILE=staging
```

**Variables:**
- `ACCOUNT`: Target environment (default: `sandbox`)
- `AWS_PROFILE`: AWS CLI profile (default: `awsclifranco-admin`)
- `TF_FLAGS`: Additional terraform flags (e.g., `TF_FLAGS=-upgrade`)

## Terraform Architecture

Multi-stack pattern with environment separation:

**Stack Discovery:** Makefile auto-detects stacks from `terraform/*/` directories

**State Management:**
- Backend config via `state.conf` at repo root (if exists)
- Stack-specific keys: `$(PROJECT_NAME)/<stack>/$(ACCOUNT)/terraform.tfstate`
- Per-environment tfvars: `terraform/environmental/env/<env>.tfvars`

**Environmental Stack** (`terraform/environmental/`):
- Currently bootstrapped but empty
- Will contain: API Gateway, custom domain, ACM cert, Lambda functions, Cognito, DynamoDB, Route53
- Multi-environment support via tfvars: sandbox, staging, uat, production
- Required providers: AWS >= 6.18.0
- Terraform version: >= 1.13.4

## Certificate Authority Structure

**3-tier PKI chain:**
1. Root CA (self-signed, 10yr) → 2. Intermediate CA (signed by Root, 5yr) → 3. Client certs (signed by Intermediate, 1yr)

**Storage:**
- Truststore: S3 bucket with chain bundle (IntermediateCA.pem + RootCA.pem)
- Private keys: AWS Parameter Store (SecureString)

**Operations:** CA scripts in [ca-operations/scripts/](ca-operations/scripts/) (manual CI trigger, one-time bootstrap)

## Planned Directory Structure

```
ca-operations/          # CA management (manual CI trigger)
├── scripts/            # bootstrap_ca.py, provision_client.py, revoke_client.py, upload_truststore.py
├── terraform/          # s3-truststore.tf, secrets-manager.tf
└── tests/

api-infrastructure/     # API Gateway + services
├── terraform/          # api-gateway.tf, lambda-authorizer.tf, cognito.tf, dynamodb.tf, route53.tf, acm.tf
├── src/
│   ├── authorizer/     # Lambda authorizer code
│   └── token-endpoint/ # Token issuance Lambda
└── tests/
```

## Implementation Roadmap

Reference [README.md](README.md) for full implementation plan (items 1-12), including:
- uv project init (Python 3.13.7)
- CA operations scripts + terraform for S3 truststore
- API Gateway with custom domain + ACM cert
- /token endpoint with Cognito integration
- Lambda custom authorizer with mTLS + token validation
- Docker-based Lambda packaging with uv

## AWS Resources

**Custom Domain:** ACM cert required for TLS, associated with API Gateway
**mTLS:** Only works with custom domains; S3 truststore mandatory (PEM bundle)
**Auth Flow:** Cognito client_credentials → /token endpoint validates mTLS cert metadata from DynamoDB → issues token
**Authorizer:** Receives mTLS cert metadata via request context for validation

## Default Tags

All AWS resources auto-tagged:
- `franco:terraform_stack`: `aws-api-gateway-mtls`
- `franco:managed_by`: `terraform`
- `franco:environment`: `<account_name>`
