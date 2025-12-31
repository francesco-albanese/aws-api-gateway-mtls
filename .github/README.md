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

### 3. Configure GitHub Environment Secret

Set `AWS_ROLE_ARN` for sandbox environment:

```bash
gh secret set AWS_ROLE_ARN \
  --env sandbox \
  --body "arn:aws:iam::645275603781:role/TerraformRole"
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

- **staging**: Account TBD
- **uat**: Account TBD
- **production**: Account TBD

Each requires:
1. OIDC provider creation in target account
2. TerraformRole trust policy update
3. GitHub environment secret configuration
