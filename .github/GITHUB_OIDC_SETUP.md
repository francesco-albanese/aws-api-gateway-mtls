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

### 3. Configure GitHub Environment Secrets

Set secrets per GitHub environment using `--env`. Workflows reference generic names (`secrets.AWS_ROLE_ARN`, `secrets.ECR_REGISTRY`, `secrets.AWS_ACCOUNT_ID`) resolved via the `environment:` block.

```bash
# Sandbox
gh secret set AWS_ROLE_ARN --env sandbox \
  --body "arn:aws:iam::645275603781:role/terraform"
gh secret set ECR_REGISTRY --env sandbox \
  --body "645275603781.dkr.ecr.eu-west-2.amazonaws.com"
gh secret set AWS_ACCOUNT_ID --env sandbox \
  --body "645275603781"

# Staging
gh secret set AWS_ROLE_ARN --env staging \
  --body "arn:aws:iam::208318252599:role/terraform"
gh secret set ECR_REGISTRY --env staging \
  --body "208318252599.dkr.ecr.eu-west-2.amazonaws.com"
gh secret set AWS_ACCOUNT_ID --env staging \
  --body "208318252599"

# UAT
gh secret set AWS_ROLE_ARN --env uat \
  --body "arn:aws:iam::393766496546:role/terraform"
gh secret set ECR_REGISTRY --env uat \
  --body "393766496546.dkr.ecr.eu-west-2.amazonaws.com"
gh secret set AWS_ACCOUNT_ID --env uat \
  --body "393766496546"

# Production
gh secret set AWS_ROLE_ARN --env production \
  --body "arn:aws:iam::165835313193:role/terraform"
gh secret set ECR_REGISTRY --env production \
  --body "165835313193.dkr.ecr.eu-west-2.amazonaws.com"
gh secret set AWS_ACCOUNT_ID --env production \
  --body "165835313193"
```

**Note:** Environment-level secrets are resolved automatically when a job specifies `environment: <name>`. Workflows use generic names (e.g. `secrets.AWS_ROLE_ARN`) — no suffix needed.

## Terraform Deployment Flow

Deploy stacks in order:

```text
ECR → Lambda Build → Environmental
```

| Step | Workflow               | Purpose                                |
| ---- | ---------------------- | -------------------------------------- |
| 1    | `ecr-deploy.yml`       | Create ECR repositories (once per env) |
| 2    | `lambda-build.yml`     | Build & push Lambda Docker images      |
| 3    | `terraform-deploy.yml` | Deploy API Gateway, Lambda, etc.       |

```bash
# Full deployment sequence
gh workflow run ecr-deploy.yml -f environment=sandbox
gh workflow run lambda-build.yml -f environment=sandbox
gh workflow run terraform-deploy.yml -f environment=sandbox
```

## Next Steps

Repeat for remaining environments:

- **staging**: Account 208318252599
- **uat**: Account 393766496546
- **production**: Account 165835313193

Each requires:

1. OIDC provider creation in target account
2. `terraform` role trust policy update
3. GitHub environment secrets (`AWS_ROLE_ARN`, `ECR_REGISTRY`, `AWS_ACCOUNT_ID`)
