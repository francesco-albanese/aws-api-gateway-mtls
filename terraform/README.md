# Terraform Multi-Stack Architecture

## Overview

Multi-stack pattern: bootstrap → ECR → environmental → client provisioning.

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

**Purpose:** Regular infrastructure (API Gateway, Lambda, DynamoDB, Route53)

**Certificate Integration:**

- Reads certificates via data sources (`data.tf`)
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

---

### ecr/

**Purpose:** ECR repositories for Lambda container images (health + authorizer)

**Resources:**

- ECR repo: `{project}-health-lambda`
- ECR repo: `{project}-authorizer-lambda`
- Lifecycle policies: keep last 5 images
- Scan on push enabled, `prevent_destroy` lifecycle

**Deployment:**

- Triggered via: `.github/workflows/ecr-deploy.yml` (manual workflow dispatch)
- Frequency: Once per environment, MUST run before environmental stack
- State key: `aws-api-gateway-mtls/ecr/{ACCOUNT}/terraform.tfstate`

**Usage:**

```bash
make ecr-init ACCOUNT=sandbox
make ecr-plan ACCOUNT=sandbox
make ecr-apply ACCOUNT=sandbox
```

---

### client-provisioning/

**Purpose:** Store client cert metadata in DynamoDB + client keys/certs in SSM

**Resources:**

- DynamoDB table items: cert metadata (serialNumber, client_id, clientName, status, issuedAt, expiry, ttl)
- SSM parameters per client:
  - `/{project}/{env}/clients/{client_id}/private-key` (SecureString)
  - `/{project}/{env}/clients/{client_id}/certificate` (String)

**Deployment:**

- Triggered via: `.github/workflows/client-provision.yml`
- Frequency: When provisioning new clients or re-issuing certs
- Dependencies: certificate-bootstrap + environmental must run first
- State key: `aws-api-gateway-mtls/client-provisioning/{ACCOUNT}/terraform.tfstate`

**Usage:**

```bash
make client-provisioning-init ACCOUNT=sandbox
make client-provisioning-plan ACCOUNT=sandbox
make client-provisioning-apply ACCOUNT=sandbox
```

---

### Note: Intermediate CA Rotation

Rotation updates SSM parameters, DynamoDB metadata, and S3 truststore directly via Python scripts — no Terraform step needed. Resources already exist from certificate-bootstrap + client-provisioning stacks.
