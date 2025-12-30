# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AWS API Gateway HTTP regional endpoint with mTLS enforcement. Uses certificate chain mechanism (Root CA → Intermediate CA → Client certs) with S3 truststore, custom domains, ACM certs, Cognito client_credentials flow, and DynamoDB for certificate metadata validation.

## Build System

Makefile-based build system with modular makefiles in [makefiles/](makefiles/).

## Terraform Architecture

Multi-stack pattern with environment separation:

**Stack Discovery:** Makefile auto-detects stacks from `terraform/*/` directories

**State Management:**

- Backend config via `state.conf` at repo root (if exists)
- Stack-specific keys: `$(PROJECT_NAME)/<stack>/$(ACCOUNT)/terraform.tfstate`
- Per-environment tfvars: `terraform/environmental/env/<env>.tfvars`

**Environmental Stack** (`terraform/environmental/`):

- Will contain: API Gateway, custom domain, ACM cert, Lambda functions, Cognito, DynamoDB, Route53
- Multi-environment support via tfvars: sandbox, staging, uat, production

## Certificate Authority Structure

**3-tier PKI chain:**

1. Root CA (self-signed, 10yr) → 2. Intermediate CA (signed by Root, 5yr) → 3. Client certs (signed by Intermediate, 1yr)

**Storage:**

- Truststore: S3 bucket with chain bundle (IntermediateCA.pem + RootCA.pem)
- Private keys: AWS Parameter Store (SecureString)

## Implementation Roadmap

Reference [README.md](README.md) for full implementation plan validation

## Python rule

Imports go always at the top of the files, never mid file imports
