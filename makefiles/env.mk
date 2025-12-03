# makefiles/env.mk
# Environment setup and configuration module
# Handles Python virtual environment management, dependency installation, and .env file setup

.PHONY: check-venv install-uv setup-venv install-deps sync

check-venv: ## Ensure uv is installed and Python virtual environment exists
check-venv: install-uv setup-venv
	@echo "Virtual environment setup complete"

# Internal target: Check if uv is installed, install if needed
install-uv:
	@if ! command -v uv >/dev/null 2>&1; then \
		echo "Installing uv..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	else \
		echo "uv is already installed"; \
	fi

setup-venv:
	@if [ ! -d ".venv" ]; then \
		echo "Creating Python virtual environment in .venv..."; \
		uv venv --python 3.13; \
		source .venv/bin/activate; \
		echo "Virtual environment created at .venv"; \
	else \
		echo "Virtual environment already exists at .venv"; \
	fi

install-deps: ## Install Python dependencies in the virtual environment
install-deps: check-venv
	@echo "Installing Python dependencies from pyproject.toml..."
	@uv sync --dev

sync: ## Sync Python dependencies using uv (requires existing venv)
sync: install-uv
	@if [ ! -d ".venv" ]; then \
		echo "Error: Virtual environment not found at .venv"; \
		echo "Run 'make check-venv' or 'make setup-venv' first."; \
		exit 1; \
	fi
	@echo "Syncing Python dependencies from pyproject.toml..."
	@uv sync --dev
