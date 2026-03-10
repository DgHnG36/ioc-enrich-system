.PHONY: help go proto-go python proto-python proto clean-proto test \
	docker-build docker-up docker-down k8s-dev k8s-prod k8s-down

help:
	@echo "IoC Enrich System - Root Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make go            Generate Go protobuf code (via proto/Makefile)"
	@echo "  make python        Generate Python protobuf code (via proto/Makefile)"
	@echo "  make proto         Generate both Go and Python protobuf code"
	@echo "  make clean-proto   Clean generated protobuf artifacts"
	@echo "  make test          Run unit tests from test/Makefile"
	@echo "  make docker-build  Build all Docker images"
	@echo "  make docker-up     Start all services (Docker Compose)"
	@echo "  make docker-down   Stop all services"
	@echo "  make k8s-dev       Deploy to Kubernetes (dev overlay)"
	@echo "  make k8s-prod      Deploy to Kubernetes (production overlay)"
	@echo "  make k8s-down      Remove Kubernetes deployment"

# Backward-compatible target for users who run: make go
go: proto-go

proto-go:
	@$(MAKE) -C proto go

python: proto-python

proto-python:
	@$(MAKE) -C proto python

proto:
	@$(MAKE) -C proto generate

clean-proto:
	@$(MAKE) -C proto clean

test:
	@$(MAKE) -C test test-unit

# Docker
docker-build:
	docker build -t ioc-api-gateway:latest -f services/ioc-api-gateway/Dockerfile .
	docker build -t ioc-core:latest -f services/ioc-core/Dockerfile .
	docker build -t ti-enrichment:latest -f services/ti-enrichment/Dockerfile .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

# Kubernetes
k8s-dev:
	kubectl apply -k infrastructure/k8s/overlays/dev/

k8s-prod:
	kubectl apply -k infrastructure/k8s/overlays/production/

k8s-down:
	kubectl delete -k infrastructure/k8s/overlays/dev/
