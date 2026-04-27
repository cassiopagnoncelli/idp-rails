SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help bundle setup lint style test check ci topology clean stats

RAILS_LOC_DIRS = lib spec
RAILS_LOC_FIND_TYPES = \( -name '*.rb' \)
RAILS_LOC_GIT_PATHS = \
	':(glob)lib/**/*.rb' \
	':(glob)spec/**/*.rb'

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

stats: ## Show current and historical LOC stats
	@current_rails_loc=$$(find $(RAILS_LOC_DIRS) -type f $(RAILS_LOC_FIND_TYPES) -print0 | xargs -0 cat | wc -l | tr -d ' ') && \
	printf "LOC\n  Current: %s\n" "$$current_rails_loc"
	@historical_rails_loc=$$(git log --numstat --format=tformat: -- $(RAILS_LOC_GIT_PATHS) | \
		awk '($$1 ~ /^[0-9]+$$/ && $$2 ~ /^[0-9]+$$/) { total += $$1 + $$2 } END { print total + 0 }') && \
	printf "  Historical: %s\n" "$$historical_rails_loc"
