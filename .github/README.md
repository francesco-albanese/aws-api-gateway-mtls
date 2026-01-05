# GitHub OIDC Setup for AWS Authentication

## Overview

Enable GitHub Actions to authenticate to AWS without long-lived credentials using OpenID Connect (OIDC) provider.

## Prerequisites

- AWS CLI configured with admin access to target account
- `gh` CLI authenticated
- Existing Terraform IAM role in AWS account

## Setup Commands

### 1. Create OIDC Provider (AWS Sandbox: 645275603781)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 1c58a3a8518e8759bf075b76b750d4f2df264fcd \
  --profile sandbox
```

### 2. Update Terraform Role Trust Policy

Preserve existing AWS SSO trust + add GitHub OIDC for repo `francesco-albanese/aws-api-gateway-mtls`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::211125516087:root"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::645275603781:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:francesco-albanese/aws-api-gateway-mtls:*"
        }
      }
    }
  ]
}
```

Apply trust policy:

```bash
aws iam update-assume-role-policy \
  --role-name TerraformRole \
  --policy-document file://trust-policy.json \
  --profile sandbox
```

### 3. Configure GitHub Repository Secrets

Set environment-specific role ARNs at repository level:

```bash
# Sandbox
gh secret set AWS_ROLE_ARN_SANDBOX \
  --body "arn:aws:iam::645275603781:role/terraform"

# Staging
gh secret set AWS_ROLE_ARN_STAGING \
  --body "arn:aws:iam::208318252599:role/terraform"

# UAT
gh secret set AWS_ROLE_ARN_UAT \
  --body "arn:aws:iam::393766496546:role/terraform"

# Production
gh secret set AWS_ROLE_ARN_PRODUCTION \
  --body "arn:aws:iam::165835313193:role/terraform"
```

**Note:** Repository-level secrets allow terraform plan validation on PRs without requiring environment approval gates. Workflow selects correct role based on target environment.

### 4. Configure ECR Registry Secrets

Required for Lambda container image builds:

```bash
gh secret set ECR_REGISTRY_SANDBOX \
  --body "645275603781.dkr.ecr.eu-west-2.amazonaws.com"

gh secret set ECR_REGISTRY_STAGING \
  --body "208318252599.dkr.ecr.eu-west-2.amazonaws.com"

gh secret set ECR_REGISTRY_UAT \
  --body "393766496546.dkr.ecr.eu-west-2.amazonaws.com"

gh secret set ECR_REGISTRY_PRODUCTION \
  --body "165835313193.dkr.ecr.eu-west-2.amazonaws.com"
```

## Terraform Deployment Flow

Deploy stacks in order:

```
ECR → Lambda Build → Environmental
```

| Step | Workflow | Purpose |
|------|----------|---------|
| 1 | `ecr-deploy.yml` | Create ECR repositories (once per env) |
| 2 | `lambda-build.yml` | Build & push Lambda Docker images |
| 3 | `terraform-deploy.yml` | Deploy API Gateway, Lambda, etc. |

```bash
# Full deployment sequence
gh workflow run ecr-deploy.yml -f environment=sandbox
gh workflow run lambda-build.yml -f environment=sandbox
gh workflow run terraform-deploy.yml -f environment=sandbox
```

## Verification

Test GitHub Actions workflow can assume role:

```bash
# Trigger workflow manually or via PR
gh workflow run terraform-deploy.yml -f environment=sandbox
```

Check workflow logs for successful AWS authentication without access key errors.

## Next Steps

Repeat for remaining environments:

- **staging**: Account 208318252599
- **uat**: Account 393766496546
- **production**: Account 165835313193

Each requires:
1. OIDC provider creation in target account
2. `terraform` role trust policy update
3. GitHub repository secret (`AWS_ROLE_ARN_<ENV>`)
