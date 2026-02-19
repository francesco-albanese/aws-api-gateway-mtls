SHELL := /bin/bash

.DEFAULT_GOAL := help

PROJECT_NAME ?= apigw-mtls
ACCOUNT ?= sandbox
AWS_PROFILE ?= sandbox-admin

include makefiles/env.mk
include makefiles/terraform.mk
include makefiles/ca.mk
include makefiles/lambda.mk
include makefiles/api.mk

.PHONY: init plan apply destroy validate fmt test lint lint-fix

test: ## Run all tests (lambdas + ca_operations)
test: lambda-test ca-test

lint: ## Lint all code
lint: lambda-lint ca-lint

lint-fix: ## Fix all lint issues
lint-fix: lambda-lint-fix ca-lint-fix