# Client Provisioning and testing

## How to provision a new client

- Manually run Github workflow [client-provision](../.github/workflows/client-provision.yml)
- Reads the config file per environment, [example](./sandbox.json)
- extracts the client ids to be provisioned
- creates a private+public key pair
- signs the CSR with the client's private key
- fetches the intermediate CA key and cert from SSM Parameter Store
- Intermediate CA issues certificate
- Client private key, public cert and certificate metadata are stored in AWS via Terraform

## GitHub Workflow Provisioning

The [`client-provision.yml`](../.github/workflows/client-provision.yml) workflow automates provisioning:

1. Reads config per environment (e.g., [`clients/sandbox.json`](./sandbox.json)) containing client IDs
2. For each client: generates key pair, creates CSR and generates public pem certificate signed by Intermediate CA fetched from SSM
3. Stores private key and cert in SSM, uploads metadata in DynamoDB via Terraform (`client-provisioning` stack)

**Triggers on:**

- Manual workflow dispatch (select environment)
- Automatically on PR merge to `main` when `clients/*.json` changes

## Manual test

Manual testing of health endpoint with mTLS certificates.

### Quick (via Make)

```bash
make curl-health                                    # defaults (sandbox, api-client-001)
make curl-health ACCOUNT=uat CLIENT_ID=api-client-002
make curl-health-verbose                            # TLS handshake debug output
make curl-health-clean                              # wipe cached certs
```

### Step-by-step

## Pull Certs from SSM

```bash
# Set vars
PROJECT="apigw-mtls"
ENV="sandbox"  # sandbox|uat|staging|production
CLIENT_ID="api-client-001"

# Get certificate (String param)
aws ssm get-parameter \
  --name "/${PROJECT}/${ENV}/clients/${CLIENT_ID}/certificate" \
  --query 'Parameter.Value' --output text > /tmp/client.pem

# Get private key (SecureString - requires decryption)
aws ssm get-parameter \
  --name "/${PROJECT}/${ENV}/clients/${CLIENT_ID}/private-key" \
  --with-decryption \
  --query 'Parameter.Value' --output text > /tmp/client.key
```

## Test Health Endpoint

```bash
API_URL="https://api-sandbox.francescoalbanese.dev"

curl -v \
  --cert /tmp/client.pem \
  --key /tmp/client.key \
  "${API_URL}/health"
```

## Expected Response

```json
{
  "status": "healthy",
  "mtls": {
    "enabled": true,
    "clientCN": "api-client-001",
    "serialNumber": "...",
    "validity": {
      "notBefore": "...",
      "notAfter": "..."
    }
  }
}
```

## Cleanup

```bash
rm /tmp/client.pem /tmp/client.key
```
