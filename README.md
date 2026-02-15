# AWS API Gateway mTLS

The goal of this project is to create an AWS API Gateway HTTP regional endpoint with mTLS enforced. Mutual TLS is very common in finance industry for machine to machine communication. It gives an extra layer of security due to the fact that both the server and the client have to present certificates at handshake.

## Technical Challenge

AWS API Gateway requires a custom domain for mTLS - cannot enforce client certificate validation using the default `execute-api` endpoints.An S3 Trust Store is also required, with a PEM bundle containing the certificate chain.

## Architecture Highlights

**mTLS Trust Chain**

- Self-signed Root CA with offline key storage (Parameter Store, SSE-KMS)
- Intermediate CA signed by Root CA via certificate signing request showing PKI (Public Key Infrastructure) best practices
- Clients certs signed by Intermediate CA via CSR
- S3 truststore with certs bundle is used for API Gateway client cert validation
- Lambda authorizer verifies cert metadata (serial and client_id) against DynamoDB entries for each provisioned client

**Key Design Decisions**

- **Self signed CAs vs Cloudflare CA vs AWS ACM private CA**: Went for self signed root CA to avoid AWS prohibitive operational costs ($400 per month) and Cloudflare requirements for an enterprise plan which is also quite expensive ($200 per month). This implementation requires manual rotation, issuance and custom observability/auditing
- **Parameter Store over Secrets Manager**: $0/month vs $0.40/secret/month
- **Monorepo with separate Terraform stacks**: Better isolation in infrastructure dependencies
- **Lambda authorizer**: validates mTLS client certificates directly via DynamoDB metadata lookup

**Certificate Flow**

1. Client presents cert during TLS handshake
2. API Gateway validates against S3 truststore looking at the certificate chain (Root + Intermediate)
3. Lambda authorizer receives `event.requestContext.authentication.clientCert`
4. DynamoDB lookup: serial number, client_id, revocation status, identity validation
5. Authorizer context injected for downstream service consumption

## Deployment

**Order-dependent stacks**:

1. [ca-bootstrap workflow](./.github/workflows/ca-bootstrap.yml)

- run manually only once (or for rotation purposes)
- creates certificate chain and S3 truststore bundle
- uploads truststore to S3

2. [ecr-deploy](./.github/workflows/ecr-deploy.yml)

- creates elastic container registry images for Lambdas

3. [lambda-build](./.github/workflows/lambda-build.yml)

- builds Lambdas (health, authorizer) with a shared Dockerfile parameterized by `LAMBDA_NAME` build argument
- 3 stage multi build: python `uv` dependencies, OTEL instrumentation and final runtime
- builds python ARM64 runtime architecture using public image `public.ecr.aws/lambda/python:3.13-arm64`

4. [terraform-deploy workflow](./.github/workflows/terraform-deploy.yml)

- deploys resources in terraform environmental stack such as api gateway, lambdas, DynamoDB

5. [ca-rotate-intermediate workflow](./.github/workflows/ca-rotate-intermediate.yml)

- rotates intermediate CA by generating new intermediate cert signed by root CA from SSM
- re-issues all active client certificates with the new rotated intermediate CA
- re uploads secrets in SSM Parameter store, cert metadata in DynamoDB, and S3 truststore

## Security

Root CA keys stored in SSM Parameter Store (SecureString, KMS-encrypted). In production, root CA keys would be managed via AWS CloudHSM.

## Observability

- OTEL instrumentation
- Cloudwatch Insights
- Cloudwatch application signals

## Client provisioning

[Client Provisioning](./clients/README.md)
