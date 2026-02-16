#!/usr/bin/env bash
set -euo pipefail

# mTLS curl helper — downloads client certs from SSM and curls the API
# Usage: scripts/curl-mtls.sh [--verbose]

PROJECT_NAME="${PROJECT_NAME:-apigw-mtls}"
ACCOUNT="${ACCOUNT:-sandbox}"
CLIENT_ID="${CLIENT_ID:-api-client-001}"
AWS_PROFILE="${AWS_PROFILE:-awsclifranco-admin}"
DOMAIN_NAME="${DOMAIN_NAME:-francescoalbanese.dev}"
ENDPOINT="${ENDPOINT:-/health}"

VERBOSE=""
for arg in "$@"; do
  case "$arg" in
    --verbose|-v) VERBOSE="-v" ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

# Validate dependencies
for cmd in aws curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' is required but not installed." >&2
    exit 1
  fi
done

# Cache dir
CACHE_DIR=".tmp/certs/${ACCOUNT}/${CLIENT_ID}"
CERT_FILE="${CACHE_DIR}/client.pem"
KEY_FILE="${CACHE_DIR}/client.key"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
  echo "Using cached certs from ${CACHE_DIR}"
else
  echo "Downloading certs from SSM for ${CLIENT_ID} (${ACCOUNT})..."
  mkdir -p "$CACHE_DIR"

  if ! aws ssm get-parameter \
    --profile "$AWS_PROFILE" \
    --name "/${PROJECT_NAME}/${ACCOUNT}/clients/${CLIENT_ID}/certificate" \
    --query 'Parameter.Value' --output text > "$CERT_FILE"; then
    rm -f "$CERT_FILE"
    echo "Error: failed to fetch certificate from SSM" >&2
    exit 1
  fi

  if ! aws ssm get-parameter \
    --profile "$AWS_PROFILE" \
    --name "/${PROJECT_NAME}/${ACCOUNT}/clients/${CLIENT_ID}/private-key" \
    --with-decryption \
    --query 'Parameter.Value' --output text > "$KEY_FILE"; then
    rm -f "$CERT_FILE" "$KEY_FILE"
    echo "Error: failed to fetch private key from SSM" >&2
    exit 1
  fi

  chmod 600 "$KEY_FILE"
  echo "Certs cached in ${CACHE_DIR}"
fi

# Derive API URL — production uses api.domain, others use api-{account}.domain
if [[ "$ACCOUNT" == "production" ]]; then
  API_URL="https://api.${DOMAIN_NAME}"
else
  API_URL="https://api-${ACCOUNT}.${DOMAIN_NAME}"
fi

echo "Curling ${API_URL}${ENDPOINT}"
RESPONSE=$(curl -s -w "\n%{http_code}" ${VERBOSE:+"$VERBOSE"} \
  --cert "$CERT_FILE" \
  --key "$KEY_FILE" \
  "${API_URL}${ENDPOINT}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if echo "$BODY" | jq . 2>/dev/null; then
  :
else
  echo "HTTP ${HTTP_CODE}"
  echo "$BODY"
  exit 1
fi
