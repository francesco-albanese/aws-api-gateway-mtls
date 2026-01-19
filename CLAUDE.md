# Project Overview

AWS API Gateway HTTP regional endpoint with mTLS enforcement. Uses certificate chain mechanism (Root CA → Intermediate CA → Client certs) with S3 truststore, custom domains, ACM certs, Cognito client_credentials flow, and DynamoDB for certificate metadata validation.

## Package manager

- python 3.13.7 with `uv` package manager

## Tech stack

- aws services with `boto3`
- terraform deployment via Github actions and workflows
- [Github Actions and workflows](.github/)
- [Instructions on what operations to run on CI and what order](.github/README.md)

## Formatting, linting, type checks

- `prek run --all-files`

## Rules

[Testing rules](.claude/rules/testing.md)
[Lambda rules](.claude/rules/lambda.md)
[Lint rules](.claude/rules/linting.md)
