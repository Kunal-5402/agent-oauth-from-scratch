# Everyday commands. Run `make` with no target to see the list.
#
# Nothing here is required. Every target is a thin wrapper over a uv command,
# so you can always run the underlying tool directly.

SHELL := /bin/bash
.DEFAULT_GOAL := help

ENV_FILE := .env
PORT ?= 8000

# Load .env through the shell, never through make's `include`. The shell strips
# the quotes around a value such as OAUTH_CLIENT_SCOPES="finance:read reports:read".
# make would keep them and hand the server a broken scope list.
LOAD_ENV := set -a && source $(ENV_FILE) && set +a

.PHONY: help setup install hooks env db-up db-down db-shell run test lint format check token clean

help: ## Show this list
	@echo "Agent OAuth authorization server"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Start here:  make setup && make run"

setup: install hooks env db-up ## Install dependencies, hooks, a local .env, and the database
	@echo
	@echo "Ready. Start the server with: make run"

install: ## Install runtime and development dependencies
	uv sync --all-groups

hooks: ## Install the pre-commit hooks into .git/hooks
	uv run pre-commit install

env: ## Create .env from .env.example, with a fresh random client secret
	@if [ -f $(ENV_FILE) ]; then \
		echo "$(ENV_FILE) already exists. Leaving it alone."; \
	else \
		secret=$$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))'); \
		sed "s|^OAUTH_CLIENT_SECRET=.*|OAUTH_CLIENT_SECRET=$$secret|" .env.example > $(ENV_FILE); \
		echo "Wrote $(ENV_FILE) with a freshly generated OAUTH_CLIENT_SECRET."; \
	fi

db-up: ## Start Postgres and wait until it is accepting connections
	docker compose up -d
	@until [ "$$(docker inspect -f '{{.State.Health.Status}}' agent-oauth-postgres 2>/dev/null)" = "healthy" ]; do sleep 1; done
	@echo "Postgres is ready on 127.0.0.1:5433 (databases: oauth, oauth_test)."

db-down: ## Stop Postgres and delete its data
	docker compose down -v

db-shell: ## Open psql against the development database
	docker compose exec postgres psql -U oauth -d oauth

run: ## Start the authorization server with reload (PORT=8000)
	@test -f $(ENV_FILE) || { echo "No $(ENV_FILE). Run: make env"; exit 1; }
	@docker compose ps --status running --quiet postgres >/dev/null 2>&1 || { echo "Postgres is not running. Run: make db-up"; exit 1; }
	$(LOAD_ENV) && uv run uvicorn src.main:app --reload --port $(PORT)

test: db-up ## Run the test suite (starts the database if it is down)
	uv run pytest -q

lint: ## Report lint problems and fix what can be fixed
	uv run ruff check --fix .

format: ## Format the code
	uv run ruff format .

check: db-up ## Everything CI runs: lint, format check, tests
	uv run ruff check .
	uv run ruff format --check .
	uv run pytest -q

token: ## Request an access token from a running server
	@test -f $(ENV_FILE) || { echo "No $(ENV_FILE). Run: make env"; exit 1; }
	@$(LOAD_ENV) && curl -sS \
		--data-urlencode grant_type=client_credentials \
		--data-urlencode client_id="$$OAUTH_CLIENT_ID" \
		--data-urlencode client_secret="$$OAUTH_CLIENT_SECRET" \
		--data-urlencode scope=reports:read \
		http://127.0.0.1:$(PORT)/oauth/token

clean: ## Remove caches. The signing key under keys/ is never touched
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache
	@echo "Caches removed. keys/ and .env are untouched."
