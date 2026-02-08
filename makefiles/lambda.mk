# Lambda build and management
LAMBDA_DIR := lambdas

.PHONY: lambda-build lambda-build-% lambda-test lambda-test-% lambda-lint lambda-lint-% lambda-lint-fix lambda-lint-fix-%

lambda-build: ## Build all Lambda container images locally
	@for dir in $(LAMBDA_DIR)/*/; do \
		name=$$(basename $$dir); \
		echo "Building Lambda: $$name"; \
		docker build --platform linux/arm64 --build-arg LAMBDA_NAME=$$name -t mtls-$$name-lambda:local $(LAMBDA_DIR); \
	done

lambda-build-%: ## Build specific Lambda (e.g., lambda-build-health)
	@echo "Building Lambda: $*"
	@docker build --platform linux/arm64 --build-arg LAMBDA_NAME=$* -t mtls-$*-lambda:local $(LAMBDA_DIR)

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
	@for dir in $(LAMBDA_DIR)/*/; do \
		name=$$(basename $$dir); \
		echo "Linting Lambda: $$name"; \
		(cd $$dir && uv run ruff check . && uv run ruff format --check .); \
	done

lambda-lint-%: ## Lint specific Lambda
	@echo "Linting Lambda: $*"
	@cd $(LAMBDA_DIR)/$* && uv run ruff check . && uv run ruff format --check .

lambda-lint-fix: ## Fix Lambda lint issues
	@for dir in $(LAMBDA_DIR)/*/; do \
		name=$$(basename $$dir); \
		echo "Fixing Lambda: $$name"; \
		(cd $$dir && uv run ruff check --fix . && uv run ruff format .); \
	done

lambda-lint-fix-%: ## Fix specific Lambda lint
	@echo "Fixing Lambda: $*"
	@cd $(LAMBDA_DIR)/$* && uv run ruff check --fix . && uv run ruff format .
