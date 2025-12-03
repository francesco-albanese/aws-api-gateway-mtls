# aws-api-gateway-mtls

The goal of this project is to create an AWS API Gateway HTTP regional endpoint with mTLS enforced.

- mTLS works only with custom domains in AWS
- an S3 Trust Store is **required**, with a PEM bundle containing the certificate chain
- a separate ACM cert is required to enable TLS for the custom domain
- an authentication flow with token issuance will be implemented with Cognito client_credentials flow
- a `/token` endpoint will check the mTLS certificate metadata stored in DynamoDB to perform some validation checks before issuing the token
- use Route53 health checks
- the `authorizer` will receive the mTLS certificate metadata via request context to perform checks
- The project will use a certificate chain mechanism for the mTLS, which is more secure. So we need to generate a Root CA

```bash
# Root CA private key
openssl genrsa -out RootCA.key 4096

# Root CA certificate (self-signed)
openssl req -x509 -new -nodes \
  -key RootCA.key \
  -sha256 -days 3650 \
  -out RootCA.pem \
  -subj "/C=US/ST=CA/O=Portfolio/CN=Portfolio Root CA"
```

then an intermediate CA

```bash
# Intermediate CA private key
openssl genrsa -out IntermediateCA.key 4096

# Intermediate CA CSR
openssl req -new -key IntermediateCA.key \
  -out IntermediateCA.csr \
  -subj "/C=US/ST=CA/O=Portfolio/CN=Portfolio Issuing CA"

# Root CA signs Intermediate CA
openssl x509 -req -in IntermediateCA.csr \
  -CA RootCA.pem -CAkey RootCA.key \
  -CAcreateserial -out IntermediateCA.pem \
  -days 1825 -sha256 \
  -extensions v3_ca -extfile <(cat <<EOF
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF
)
```

create a CSR (certificate signing request) and sign it with the intermediate CA

```bash
# Client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/O=Portfolio/CN=device-001"

# Intermediate CA signs it
openssl x509 -req -in client.csr \
  -CA IntermediateCA.pem -CAkey IntermediateCA.key \
  -CAcreateserial -out client.pem \
  -days 365 -sha256
```

And eventually create the certificate chain to upload to S3

```bash
# Combine Intermediate + Root (order matters!)
cat IntermediateCA.pem RootCA.pem > truststore.pem

# Upload to S3
aws s3 cp truststore.pem s3://truststore-bucket/truststore.pem
```

- the certs will be stored in AWS parameter store as a SecureString

Based on the directory structure defined below and the flow of how the application should work the following logic must be implemented:

1. initialize a uv project at the root of this repository pinning the python version to 3.13.7
2. create a venv defining a helpful make file exactly like this /Users/francescoalbanese/Documents/Development/python-token-generator/makefiles/env.mk
3. create ca-operations python scripts to create root ca, intermediate ca. Define the terraform to create the s3 truststore, create the chain for truststore and upload to the s3 bucket
4. the ca-operations ideally will be triggered via CI manually (once)
5. focus on terraform/environmental , define an API Gateway, a custom domain to associate to API Gateway with a SSL/TLS cert issues by ACM. Questions: can terraform issue a custom domain directly talking to AWS APIs? same for ACM, does it have to be a manual operation or Terraform can do it?
6. once the custom domain and the ACM are issued, they have to be associated with the AWS API Gateway
7. create /token endpoint resource in api gateway
8. associate a python lambda to it
9. create a cognito resource configured with client_credentials flow
10. research what's the best way to package a python lambda with uv using a docker image to make sure the build of the lambda works correctly when uploaded to AWS
11. implement the logic of the lambda to issue a Cognito token
12. implement another endpoint with a lambda custom authorizer in between that checks the validity of the cognito token and the mTLS details before forwarding the connection to the endpoint itself which will return a simple 200

## Directory structure

The directory structure of the project will be similar to the following:

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
