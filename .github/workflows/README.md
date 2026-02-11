# Workflows

## Deployment Order

```
ca-bootstrap → ecr-deploy → lambda-build → terraform-deploy → client-provision
                                                              ↳ ca-rotate-intermediate (manual, post-deploy)
```

## Overview

| Workflow                                           | Trigger                                     | Purpose                                     | Dependencies                   |
| -------------------------------------------------- | ------------------------------------------- | ------------------------------------------- | ------------------------------ |
| [`ca-bootstrap.yml`](ca-bootstrap.yml)             | Manual                                      | One-time CA cert provisioning per env       | None                           |
| [`ecr-deploy.yml`](ecr-deploy.yml)                 | Manual                                      | Create ECR repos (once per env)             | ca-bootstrap                   |
| [`lambda-build.yml`](lambda-build.yml)             | Manual / automatic when PR merged to `main` | Builds + pushes Lambda Docker images to ECR | ecr-deploy                     |
| [`terraform-deploy.yml`](terraform-deploy.yml)     | Auto plan on PR / manual apply              | Deploy API Gateway, Lambda, DynamoDB infra  | ecr-deploy, lambda-build       |
| [`client-provision.yml`](client-provision.yml)     | Manual                                      | Provision mTLS client certificates          | ca-bootstrap, terraform-deploy |
| [`ca-rotate-intermediate.yml`](ca-rotate-intermediate.yml) | Manual | Rotate intermediate CA + re-issue client certs | ca-bootstrap, client-provision |
| [`claude-code-review.yml`](claude-code-review.yml) | Auto on PR (opened/synchronize)             | Claude AI code review                       | None                           |
| [`claude.yml`](claude.yml)                         | Auto on `@claude` mention                   | Claude integration for issues/PRs           | None                           |

## Details

### ca-bootstrap.yml

Generates Root + Intermediate CA certs, creates S3 truststore, stores keys/certs in SSM. Runs once per environment. Cleans up local artifacts after deploy.

### ecr-deploy.yml

Creates ECR repositories for Lambda container images. Must run before `lambda-build` and `terraform-deploy`. One-time per environment.

### lambda-build.yml

Detects Lambda directories, builds Docker images for ARM64 architecture, so to avoid incompatibility issues for Python wheels at Lambda runtime. It then pushes to ECR on AWS. Uses matrix strategy for parallel builds. Auto-triggers on `lambdas/**` changes to main.

### terraform-deploy.yml

Terraform plan runs automatically on PRs, apply runs manually and it's only allowed from `main` branch (PR merge). Deploys environmental stack (API Gateway, Lambda, DynamoDB, Route53).

### client-provision.yml

Reads `clients/{env}.json` config, generates key pairs, signs CSR with Intermediate CA from SSM, stores certs in SSM + metadata in DynamoDB via Terraform. Auto-triggers on `clients/*.json` changes.

### ca-rotate-intermediate.yml

Generates new Intermediate CA signed by Root CA (from SSM), re-issues all active client certs, updates SSM + DynamoDB + S3 truststore. Defaults to dry-run mode. Environment protection rules provide approval gate for production.

### claude-code-review.yml

Automated PR review by Claude. Reviews code quality, bugs, performance, security, test coverage.

### claude.yml

Responds to `@claude` mentions in issues/PRs/comments. Uses `anthropics/claude-code-action@v1`.
