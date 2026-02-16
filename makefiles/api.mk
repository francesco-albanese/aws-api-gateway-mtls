# makefiles/api.mk
# API testing module for mTLS curl operations

CLIENT_ID ?= api-client-001
DOMAIN_NAME ?= francescoalbanese.dev

.PHONY: curl-health curl-health-verbose curl-health-clean

curl-health: ## Curl health endpoint with mTLS (ACCOUNT=sandbox CLIENT_ID=api-client-001)
	@PROJECT_NAME=$(PROJECT_NAME) ACCOUNT=$(ACCOUNT) CLIENT_ID=$(CLIENT_ID) \
		AWS_PROFILE=$(AWS_PROFILE) DOMAIN_NAME=$(DOMAIN_NAME) ENDPOINT=/health \
		bash scripts/curl-mtls.sh

curl-health-verbose: ## Curl health endpoint with verbose TLS output
	@PROJECT_NAME=$(PROJECT_NAME) ACCOUNT=$(ACCOUNT) CLIENT_ID=$(CLIENT_ID) \
		AWS_PROFILE=$(AWS_PROFILE) DOMAIN_NAME=$(DOMAIN_NAME) ENDPOINT=/health \
		bash scripts/curl-mtls.sh --verbose

curl-health-clean: ## Remove cached mTLS certificates
	@echo "Removing cached certs..."
	@rm -rf .tmp/certs
