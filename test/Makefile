.PHONY: help setup \
	test test-unit test-unit-go test-unit-python \
	test-integration test-integration-go test-integration-python test-integration-quick \
	test-e2e test-performance test-performance-load test-performance-stress gen-api-token \
	test-all test-services-health start-services stop-services test-ci report clean

# Colors for output
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

# Configuration
API_GATEWAY_URL ?= http://localhost:8080
IOC_CORE_ADDR ?= localhost:50051
ENRICHMENT_ADDR ?= localhost:50052
PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
K6 ?= k6
DOCKER_COMPOSE ?= docker-compose
JWT_SECRET ?= test-secret-key-do-not-use-in-production

help: ## Show this help message
	@echo '${GREEN}IoC Enrichment System - Test Suite${RESET}'
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  ${YELLOW}%-20s${RESET} %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Install test dependencies
	@echo "${GREEN}Installing test dependencies...${RESET}"
	@echo "Go dependencies..."
	cd integration && go mod download
	@echo "Python dependencies..."
	$(PIP) install -r integration/requirements.txt
	@echo "Checking k6 installation..."
	@which $(K6) > /dev/null || echo "${YELLOW}Warning: k6 not found. Install from https://k6.io/${RESET}"
	@echo "${GREEN}Setup complete!${RESET}"

test: test-unit ## Run default test suite (unit tests)
	@echo "${GREEN}Default tests complete!${RESET}"

test-unit-go: ## Run Go unit tests
	@echo "${GREEN}Running Go unit tests...${RESET}"
	@set -e; \
	for mod in unit/services/ioc-core unit/services/ioc-api-gateway; do \
		echo "Running $$mod ..."; \
		cd $$mod && go test -v ./... && cd - > /dev/null; \
	done
	@echo "${GREEN}Go unit tests complete!${RESET}"

test-unit-python: ## Run Python unit tests (ti-enrichment)
	@echo "${GREEN}Running Python unit tests...${RESET}"
	$(PYTHON) -m pytest unit/services/ti-enrichment -v
	@echo "${GREEN}Python unit tests complete!${RESET}"

test-unit: test-unit-go test-unit-python ## Run all unit tests
	@echo "${GREEN}Unit tests complete!${RESET}"

test-integration-go: ## Run Go integration tests
	@echo "${GREEN}Running Go integration tests...${RESET}"
	cd integration && IOC_CORE_ADDR=$(IOC_CORE_ADDR) API_GATEWAY_URL=$(API_GATEWAY_URL) go test -v ./...
	@echo "${GREEN}Go integration tests complete!${RESET}"

test-integration-python: ## Run Python integration tests (ti-enrichment)
	@echo "${GREEN}Running Python integration tests...${RESET}"
	cd integration && ENRICHMENT_ADDR=$(ENRICHMENT_ADDR) $(PYTHON) -m pytest ti_enrichment_integration_test.py -v
	@echo "${GREEN}Python integration tests complete!${RESET}"

test-integration: test-integration-go test-integration-python ## Run integration tests (requires services running)
	@echo "${GREEN}Integration tests complete!${RESET}"

test-integration-quick: ## Run quick integration tests
	@echo "${GREEN}Running quick integration tests...${RESET}"
	cd integration && IOC_CORE_ADDR=$(IOC_CORE_ADDR) go test -v -short ./...
	cd integration && ENRICHMENT_ADDR=$(ENRICHMENT_ADDR) $(PYTHON) -m pytest ti_enrichment_integration_test.py -v
	@echo "${GREEN}Quick integration tests complete!${RESET}"

test-e2e: ## Run end-to-end tests
	@echo "${GREEN}Running end-to-end tests...${RESET}"
	@chmod +x e2e/full_workflow_test.sh
	API_GATEWAY_URL=$(API_GATEWAY_URL) ./e2e/full_workflow_test.sh
	@echo "${GREEN}E2E tests complete!${RESET}"

gen-api-token: ## Generate API token for protected /api/v1 routes
	@JWT_SECRET=$(JWT_SECRET) $(PYTHON) performance/generate_jwt.py

test-performance-load: ## Run load tests
	@echo "${GREEN}Running load tests...${RESET}"
	@which $(K6) > /dev/null || (echo "${YELLOW}Error: k6 not installed${RESET}" && exit 1)
	@set -e; \
	TOKEN="$${API_TOKEN:-$$($(PYTHON) performance/generate_jwt.py --secret "$(JWT_SECRET)")}"; \
	echo "Using API token for load test"; \
	API_GATEWAY_URL=$(API_GATEWAY_URL) API_TOKEN="$$TOKEN" $(K6) run performance/load_test.js
	@echo "${GREEN}Load tests complete!${RESET}"

test-performance-stress: ## Run stress tests
	@echo "${GREEN}Running stress tests...${RESET}"
	@which $(K6) > /dev/null || (echo "${YELLOW}Error: k6 not installed${RESET}" && exit 1)
	@set -e; \
	TOKEN="$${API_TOKEN:-$$($(PYTHON) performance/generate_jwt.py --secret "$(JWT_SECRET)")}"; \
	echo "Using API token for stress test"; \
	API_GATEWAY_URL=$(API_GATEWAY_URL) API_TOKEN="$$TOKEN" $(K6) run performance/stress_test.js
	@echo "${GREEN}Stress tests complete!${RESET}"

test-performance: test-performance-load test-performance-stress ## Run all performance tests

test-all: test-unit test-integration test-e2e ## Run all tests (requires services running)
	@echo "${GREEN}All tests complete!${RESET}"

test-services-health: ## Check if all services are healthy
	@echo "${GREEN}Checking service health...${RESET}"
	@curl -sf $(API_GATEWAY_URL)/health > /dev/null && echo "✓ API Gateway is healthy" || echo "✗ API Gateway is not responding"
	@echo "${GREEN}Health check complete!${RESET}"

clean: ## Clean test artifacts and generated files
	@echo "${GREEN}Cleaning test artifacts...${RESET}"
	rm -f integration/*.log
	rm -f e2e/*.log
	rm -f performance/*.json
	rm -f performance/*.html
	@echo "${GREEN}Clean complete!${RESET}"

start-services: ## Start all services with docker-compose (from root)
	@echo "${GREEN}Starting services...${RESET}"
	$(DOCKER_COMPOSE) -f docker-compose.test.yaml up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@$(MAKE) test-services-health

stop-services: ## Stop all services
	@echo "${GREEN}Stopping services...${RESET}"
	$(DOCKER_COMPOSE) -f docker-compose.test.yaml down
	@echo "${GREEN}Services stopped${RESET}"

test-ci: ## Run tests suitable for CI/CD pipeline
	@echo "${GREEN}Running CI tests...${RESET}"
	$(MAKE) test-services-health
	$(MAKE) test-integration-quick
	$(MAKE) test-e2e
	@echo "${GREEN}CI tests complete!${RESET}"

report: ## Generate test report (requires test results)
	@echo "${GREEN}Generating test report...${RESET}"
	@echo "Test Results Summary:"
	@echo "  Integration tests: See integration/*.log"
	@echo "  E2E tests: See e2e/*.log"
	@echo "  Performance tests: See performance/*.json"
	@echo "${GREEN}Report generation complete!${RESET}"

.DEFAULT_GOAL := help
