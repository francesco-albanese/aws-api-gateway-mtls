# Terraform Multi-Stack Architecture

## Overview

Two-stack pattern separating one-time bootstrap from regular infrastructure.

## Stacks

### certificate-bootstrap/

**Purpose:** One-time CA certificate provisioning (Root CA, Intermediate CA, S3 truststore)

**Resources:**

- S3 bucket: `{account_name}-mtls-truststore-{account_id}`
- S3 object: `truststore.pem` (IntermediateCA + RootCA bundle)
- SSM parameters (4):
  - `/{project}/ca/root/private-key` (SecureString)
  - `/{project}/ca/root/certificate` (String)
  - `/{project}/ca/intermediate/private-key` (SecureString)
  - `/{project}/ca/intermediate/certificate` (String)

**Deployment:**

- Triggered via: `.github/workflows/ca-bootstrap.yml` (manual workflow dispatch)
- Frequency: Once per environment (sandbox/staging/uat/production)
- Local certificates: Generated, uploaded to AWS, then deleted for security
- State key: `aws-api-gateway-mtls/certificate-bootstrap/{ACCOUNT}/terraform.tfstate`

**Usage:**

```bash
make certificate-bootstrap-init ACCOUNT=sandbox
make certificate-bootstrap-plan ACCOUNT=sandbox
make certificate-bootstrap-apply ACCOUNT=sandbox
```

---

### environmental/

**Purpose:** Regular infrastructure (API Gateway, Cognito, Lambda, DynamoDB, Route53)

**Certificate Integration:**

- Reads certificates via data sources (`data-certificates.tf`)
- Enables automatic terraform plans on PRs

**Deployment:**

- Triggered via: `.github/workflows/terraform-deploy.yml` (auto plan on PR, manual apply)
- Frequency: Every infrastructure change
- Dependencies: certificate-bootstrap must run first per environment
- State key: `aws-api-gateway-mtls/environmental/{ACCOUNT}/terraform.tfstate`

**Usage:**

```bash
make environmental-init ACCOUNT=sandbox
make environmental-plan ACCOUNT=sandbox
make environmental-apply ACCOUNT=sandbox
```
