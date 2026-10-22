SHELL := bash
.DEFAULT_GOAL := help
IMAGE ?= ghcr.io/ahmedelgmal310/aegis-ledger

.PHONY: help test lint image up deploy smoke attack dast demo down

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS=":.*## "} {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

test: ## Run unit tests with the race detector and coverage
	cd app && go test -race -cover ./...

lint: ## Lint Go code and policies locally
	cd app && golangci-lint run ./...
	docker run --rm -v "$$PWD:/repo" -w /repo ghcr.io/kyverno/kyverno-cli:v1.19.2 test deploy/policies/tests

image: ## Build the ledger image locally
	docker build -t aegis-ledger:dev app

up: ## Create the kind cluster with Kyverno, Falco, Argo CD and Sealed Secrets
	./scripts/cluster-up.sh

deploy: ## Deploy the promoted release from main through Argo CD
	./scripts/deploy.sh

smoke: ## Functional smoke test against the cluster
	./scripts/smoke-test.sh

attack: ## Run the admission and runtime attack simulations
	SIGNED_IMAGE="$$(kubectl -n aegis get deploy ledger -o jsonpath='{.spec.template.spec.containers[0].image}')" ./scripts/attack-admission.sh
	./scripts/attack-runtime.sh

dast: ## OWASP ZAP baseline scan against the cluster
	./scripts/dast.sh

demo: up deploy smoke attack dast ## Everything, end to end

down: ## Delete the kind cluster
	kind delete cluster --name aegis
