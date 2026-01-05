# Lambda build and management
LAMBDA_DIR := lambdas

.PHONY: lambda-build lambda-build-% lambda-test lambda-lint

lambda-build: ## Build all Lambda container images locally
	@for dir in $(LAMBDA_DIR)/*/; do \
		name=$$(basename $$dir); \
		echo "Building Lambda: $$name"; \
		docker build --platform linux/arm64 -t mtls-$$name-lambda:local $$dir; \
	done

lambda-build-%: ## Build specific Lambda (e.g., lambda-build-health)
	@echo "Building Lambda: $*"
	@docker build --platform linux/arm64 -t mtls-$*-lambda:local $(LAMBDA_DIR)/$*/

lambda-test: ## Run tests for all Lambdas
	@for dir in $(LAMBDA_DIR)/*/; do \
		name=$$(basename $$dir); \
		echo "Testing Lambda: $$name"; \
		(cd $$dir && uv run pytest); \
	done

lambda-test-%: ## Test specific Lambda
	@echo "Testing Lambda: $*"
	@cd $(LAMBDA_DIR)/$* && uv run pytest

lambda-lint: ## Lint all Lambda code
	@uv run ruff check $(LAMBDA_DIR)
	@uv run ruff format --check $(LAMBDA_DIR)

lambda-lint-fix: ## Fix Lambda lint issues
	@uv run ruff check --fix $(LAMBDA_DIR)
	@uv run ruff format $(LAMBDA_DIR)
