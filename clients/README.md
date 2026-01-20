# Client Testing

Manual testing of health endpoint with mTLS certificates.

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
API_URL="https://api.${ENV}.example.com"

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
