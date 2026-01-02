SHELL := /bin/bash

.DEFAULT_GOAL := help

PROJECT_NAME ?= apigw-mtls
ACCOUNT ?= sandbox
AWS_PROFILE ?= awsclifranco-admin
terraform = AWS_PROFILE=$(AWS_PROFILE) terraform

include makefiles/env.mk
include makefiles/terraform.mk
include makefiles/ca.mk

.PHONY: init plan apply destroy validate fmt