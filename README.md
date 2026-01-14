# aws-api-gateway-mtls

The goal of this project is to create an AWS API Gateway HTTP regional endpoint with mTLS enforced.

- mTLS works only with custom domains in AWS
- an S3 Trust Store is **required**, with a PEM bundle containing the certificate chain
- a separate ACM cert is required to enable TLS for the custom domain
- an authentication flow with token issuance will be implemented with Cognito client_credentials flow
- a `/token` endpoint will check the mTLS certificate metadata stored in DynamoDB to perform some validation checks before issuing the token
- the `/health` endpoint will receive the mTLS certificate metadata via request context to perform checks

## Terraform Deployment

### Deployment Order

**IMPORTANT:** Deploy stacks in this order:

1. **ECR** (once per environment) - Creates container registries for Lambda images
2. **Lambda Build** - Pushes Docker images to ECR
3. **Environmental** - Creates API Gateway, Lambda functions, etc.

```bash
# 1. Deploy ECR first (creates repositories)
gh workflow run ecr-deploy.yml -f environment=sandbox

# 2. Build and push Lambda images
gh workflow run lambda-build.yml -f environment=sandbox

# 3. Deploy infrastructure
gh workflow run terraform-deploy.yml -f environment=sandbox
```

### PR Validation

All PRs automatically run `terraform plan` for validation. Check workflow status before merging.

### Manual Deployment

```bash
# Trigger via GitHub CLI
gh workflow run terraform-deploy.yml -f environment=sandbox
```

- the certs are stored in AWS parameter store as a SecureString

1. create /token endpoint resource in api gateway
2. associate a python lambda to it
3. create a cognito resource configured with client_credentials flow

4.  implement the logic of the lambda to issue a Cognito token
5.  implement another endpoint with a lambda custom authorizer in between that checks the validity of the cognito token and the mTLS details before forwarding the connection to the endpoint itself which will return a simple 200
