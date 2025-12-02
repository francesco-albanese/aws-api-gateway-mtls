# aws-api-gateway-mtls

The goal of this project is to create an AWS API Gateway HTTP regional endpoint with mTLS enforced.

- mTLS works only with custom domains in AWS
- an S3 Trust Store is **required**, with a PEM bundle containing the certificate chain
- a separate ACM cert is required to enable TLS for the custom domain
- an asymmetric authentication with token exchange must be implemented with Cognito client_credentials flow
- a `/token` endpoint will receive the mTLS certificate metadata to perform some validation checks
- use Route53 health checks

## Directory structure

The directory structure of the project will be like the following:

aws-api-gateway-mtls/
├── .github/workflows/
│ ├── ca-operations.yml # Manual trigger only
│ ├── api-infrastructure.yml # Automated on PR/merge
│ └── integration-tests.yml
│
├── ca-operations/ # CA management
│ ├── scripts/
│ │ ├── bootstrap_ca.py # One-time: create root CA
│ │ ├── provision_client.py # Issue client certs
│ │ ├── revoke_client.py
│ │ └── upload_truststore.py # One-time: upload to S3
│ ├── terraform/
│ │ ├── s3-truststore.tf # ONLY S3 bucket + versioning
│ │ └── secrets-manager.tf # Store CA root key
│ ├── tests/
│ └── README.md # CA operations guide
│
├── api-infrastructure/ # API Gateway + services
│ ├── terraform/
│ │ ├── main.tf
│ │ ├── api-gateway.tf
│ │ ├── lambda-authorizer.tf
│ │ ├── cognito.tf
│ │ ├── dynamodb.tf
│ │ ├── route53.tf
│ │ ├── acm.tf
│ │ └── outputs.tf
│ ├── src/
│ │ ├── authorizer/ # Lambda authorizer code
│ │ └── token-endpoint/
│ ├── tests/
│ └── README.md
│
├── docs/
│ ├── architecture.md
│ ├── ca-bootstrap.md # How to initialize CA
│ ├── client-provisioning.md
│ └── mTLS-flow.md
│
├── examples/
│ ├── client-cert-example/ # Sample provisioned cert
│ └── test-requests.sh # Demo mTLS calls
│
└── README.md # Portfolio overview
