# makefiles/ca.mk
# CA operations module for certificate authority management

.PHONY: ca-bootstrap ca-truststore ca-provision-client ca-clean

ca-bootstrap: ## Bootstrap CA for environment (ACCOUNT=sandbox)
ca-bootstrap: check-venv
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "Error: ACCOUNT not set. Usage: make ca-bootstrap ACCOUNT=sandbox"; \
		exit 1; \
	fi
	@echo "Bootstrapping CA for environment: $(ACCOUNT)"
	@OUTPUT_DIR="ca_operations/output/$(ACCOUNT)"; \
	mkdir -p "$$OUTPUT_DIR"; \
	uv run --group ca python -m ca_operations.scripts.bootstrap_ca --output-dir "$$OUTPUT_DIR"

ca-truststore: ## Create truststore bundle (ACCOUNT=sandbox)
ca-truststore: check-venv
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "Error: ACCOUNT not set. Usage: make ca-truststore ACCOUNT=sandbox"; \
		exit 1; \
	fi
	@echo "Creating truststore for environment: $(ACCOUNT)"
	@OUTPUT_DIR="ca_operations/output/$(ACCOUNT)"; \
	uv run --group ca python -m ca_operations.scripts.create_truststore \
		--ca-dir "$$OUTPUT_DIR" \
		--output "$$OUTPUT_DIR/truststore/truststore.pem"

ca-provision-client: ## Provision client certificate (ACCOUNT=sandbox CLIENT_ID=api-client-001)
ca-provision-client: check-venv
	@if [ -z "$(ACCOUNT)" ] || [ -z "$(CLIENT_ID)" ]; then \
		echo "Error: ACCOUNT and CLIENT_ID required."; \
		echo "Usage: make ca-provision-client ACCOUNT=sandbox CLIENT_ID=api-client-001"; \
		exit 1; \
	fi
	@echo "Provisioning client certificate: $(CLIENT_ID) for $(ACCOUNT)"
	@CA_DIR="ca_operations/output/$(ACCOUNT)"; \
	OUTPUT_DIR="ca_operations/output/$(ACCOUNT)/clients"; \
	uv run --group ca python -m ca_operations.scripts.provision_client \
		--client-id "$(CLIENT_ID)" \
		--ca-dir "$$CA_DIR" \
		--output-dir "$$OUTPUT_DIR"

ca-clean: ## Remove CA output for environment (ACCOUNT=sandbox)
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "Error: ACCOUNT not set. Usage: make ca-clean ACCOUNT=sandbox"; \
		exit 1; \
	fi
	@echo "Removing CA output for environment: $(ACCOUNT)"
	@rm -rf "ca_operations/output/$(ACCOUNT)"
