PNPM := corepack pnpm
COMPOSE := docker compose --env-file .env -f deploy/compose/compose.yaml

.PHONY: bootstrap generate lint typecheck test test-integration test-e2e test-security build docker-build dev up dev-down down db-migrate db-seed db-reset reset logs openapi verify ci

bootstrap:
	corepack enable
	$(PNPM) install --frozen-lockfile
	$(MAKE) generate

generate:
	$(PNPM) generate
	go generate ./services/api/...

lint:
	$(PNPM) lint
	$(PNPM) format:check
	go vet ./modules/contacts/... ./modules/customfields/... ./modules/dfir/... ./modules/identity/... ./modules/sla/... ./modules/ticketing/... ./services/api/... ./services/worker/...

typecheck:
	$(PNPM) typecheck

test:
	$(PNPM) test
	go test ./modules/contacts/... ./modules/customfields/... ./modules/dfir/... ./modules/identity/... ./modules/sla/... ./modules/ticketing/... ./services/api/... ./services/worker/...

test-integration:
	$(PNPM) test:integration

test-e2e:
	$(PNPM) test:e2e

test-security:
	$(PNPM) test:security

build:
	$(PNPM) build
	go build ./services/api/cmd/api ./services/worker/cmd/worker

docker-build:
	$(COMPOSE) --profile full build

dev:
	$(COMPOSE) --profile minimal up --build

up: dev

dev-down:
	$(COMPOSE) --profile minimal down --remove-orphans

down: dev-down

db-migrate:
	$(COMPOSE) run --rm migration

db-seed:
	$(COMPOSE) run --rm db-seed

db-reset:
	$(COMPOSE) down --volumes --remove-orphans
	$(COMPOSE) --profile minimal up --build

reset: db-reset

logs:
	$(COMPOSE) --profile minimal logs --follow

openapi:
	$(PNPM) --filter @periapsis/contracts generate

verify:
	$(PNPM) verify

ci:
	$(PNPM) ci
