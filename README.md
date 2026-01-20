# aws-api-gateway-mtls

The goal of this project is to create an AWS API Gateway HTTP regional endpoint with mTLS enforced.
Mutual TLS is very common in finance industry and gives an extra layer of security due to the fact that both the server and the client have to present certificates at handshake.

- mTLS works only with custom domains in AWS
- an S3 Trust Store is **required**, with a PEM bundle containing the certificate chain
- mTLS can be enforced at API Gateway level only when a custom domain is attached
- a separate ACM cert is required to enable TLS for a custom domain
- the `/health` endpoint, invoked by a client with both the private key and the public certificate signed by the Intermediate CA demonstrates the simple flow. It receives the mTLS certificate metadata via lambda equest context which can be used to perform authentication checks such as
  - query DynamoDB table with the cert serial number to check it matches
  - check the client id and validity of the certificate etc

## Terraform Deployment

The AWS services are deployed and managed via Terraform

### Deployment Order

**IMPORTANT:** Deploy stacks in this order:

1. **ECR** (once per environment) - Creates container registries for Lambda images
2. **Lambda Build** - Pushes Docker images to ECR
3. **Environmental** - Creates API Gateway, Lambda functions, DynamoDB tables etc

All PRs automatically run `terraform plan` for validation
