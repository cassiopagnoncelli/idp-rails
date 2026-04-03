SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help bundle setup lint style test check ci topology clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bundle: ## Install project dependencies
	bundle install

setup: bundle ## Prepare local development environment

lint: ## Run RuboCop checks
	bundle exec rubocop

style: ## Auto-correct style issues with RuboCop
	bundle exec rubocop -A

test: ## Run test suite
	bundle exec rspec

check: lint test ## Run lint and tests

ci: check ## CI-equivalent local verification

topology: ## Run RabbitMQ topology rake task
	bundle exec rake fld:topology

clean: ## Remove local test artifacts
	rm -rf coverage .rspec_status
