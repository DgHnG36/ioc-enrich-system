# IoC Enrichment System

[![CI Pipeline](https://github.com/DgHnG36/ioc-enrich-system/actions/workflows/ci.yml/badge.svg)](https://github.com/DgHnG36/ioc-enrich-system/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yaml)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?logo=kubernetes&logoColor=white)](infrastructure/k8s/)
[![gRPC](https://img.shields.io/badge/gRPC-Protocol%20Buffers-244c5a?logo=grpc&logoColor=white)](proto/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?logo=postgresql&logoColor=white)](init/init.sql)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](docker-compose.yaml)

A microservices-based **Indicator of Compromise (IoC) management and threat intelligence enrichment** platform. The system automates IoC ingestion, enrichment from multiple threat intelligence sources, and threat correlation — exposed via a REST API gateway backed by gRPC inter-service communication.

## Architecture

```
┌──────────┐      REST       ┌──────────────────┐      gRPC       ┌───────────┐      gRPC       ┌────────────────┐
│  Client   │ ──────────────> │  ioc-api-gateway │ ──────────────> │  ioc-core │ ──────────────> │ ti-enrichment  │
│           │ <────────────── │  (Go / Gin)      │ <────────────── │  (Go)     │ <────────────── │ (Python)       │
└──────────┘      JSON       │  :8080            │      Proto      │  :50051   │      Proto      │ :50052         │
                              └──────────────────┘                 └───────────┘                 └────────────────┘
                                       │                                │                               │
                                       │                                │                               │
                                       ▼                                ▼                               ▼
                                  ┌─────────┐                    ┌────────────┐               ┌──────────────────┐
                                  │  Redis   │                    │ PostgreSQL │               │ External TI APIs │
                                  │  :6379   │                    │   :5432    │               │ VT, AbuseIPDB,   │
                                  └─────────┘                    └────────────┘               │ OTX, HybridAnaly │
                                                                                              └──────────────────┘
```

### Services

| Service             | Language      | Port  | Description                                             |
| ------------------- | ------------- | ----- | ------------------------------------------------------- |
| **ioc-api-gateway** | Go (Gin)      | 8080  | REST API, JWT auth, rate limiting, CORS                 |
| **ioc-core**        | Go (gRPC)     | 50051 | IoC/Threat CRUD, enrichment orchestration, statistics   |
| **ti-enrichment**   | Python (gRPC) | 50052 | Multi-source TI enrichment with caching & rate limiting |

### Tech Stack

- **Languages**: Go 1.24, Python 3.12
- **Communication**: gRPC + Protocol Buffers, REST (Gin)
- **Database**: PostgreSQL 15
- **Cache**: Redis 7
- **Infrastructure**: Docker, Kubernetes (Kustomize), GitHub Actions CI
- **Testing**: Go testing, pytest, k6 (load/stress)

## Features

### IoC Management

- Batch upsert IoCs (IP, domain, hash, URL, file path)
- Search and filter with pagination
- Automatic enrichment from threat intelligence sources
- Expiration tracking and detection count

### Threat Intelligence

- Batch upsert threats with TTP mapping
- IoC-Threat correlation and linking
- Threat statistics and analytics

### Enrichment Sources

- **VirusTotal** — File hash, URL, domain, IP analysis
- **AbuseIPDB** — IP reputation and abuse reports
- **AlienVault OTX** — Pulse-based threat intelligence
- **Hybrid Analysis** — Sandbox-based file analysis

### Platform

- JWT authentication with configurable secrets
- Redis-based rate limiting
- gRPC health checking and keepalive
- In-memory statistics caching with singleflight pattern
- Bulk database operations for high throughput

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Go 1.22+
- Python 3.11+
- (Optional) [k6](https://k6.io/) for performance testing
- (Optional) [minikube](https://minikube.sigs.k8s.io/) for local Kubernetes

### Run with Docker Compose

```bash
# Clone the repository
git clone https://github.com/DgHnG36/ioc-enrich-system.git
cd ioc-enrich-system

# Start all services
docker compose up -d --build

# Verify health
curl http://localhost:8080/health
```

### Environment Variables

Copy and modify the API keys in `docker-compose.yaml`:

```yaml
VIRUSTOTAL_API_KEY: your_key_here
ABUSEIPDB_API_KEY: your_key_here
OTX_API_KEY: your_key_here
HYBRID_ANALYSIS_API_KEY: your_key_here
```

## API Reference

Base URL: `http://localhost:8080`

All protected endpoints require `Authorization: Bearer <JWT_TOKEN>` header.

### Health Check

```
GET /health         # Liveness
GET /ready          # Readiness (checks downstream services)
```

### IoC Endpoints

```
POST   /api/v1/iocs/batch         # Batch upsert IoCs
GET    /api/v1/iocs/:id            # Get IoC by ID
GET    /api/v1/iocs/value/:value   # Get IoC by value
POST   /api/v1/iocs/find           # Search/filter IoCs
DELETE /api/v1/iocs                # Delete IoCs
GET    /api/v1/iocs/stats          # IoC statistics
GET    /api/v1/iocs/expired        # Get expired IoCs
POST   /api/v1/iocs/enrich         # Enrich an IoC
```

### Threat Endpoints

```
POST   /api/v1/threats/batch       # Batch upsert threats
GET    /api/v1/threats/:id         # Get threat by ID
POST   /api/v1/threats/find        # Search/filter threats
DELETE /api/v1/threats              # Delete threats
GET    /api/v1/threats/stats        # Threat statistics
POST   /api/v1/threats/correlate    # Correlate threat with IoCs
POST   /api/v1/threats/link         # Link IoCs to threat
POST   /api/v1/threats/unlink       # Unlink IoCs from threat
```

### Enrichment Endpoints

```
POST   /api/v1/enrichment/enrich    # Enrich indicator
POST   /api/v1/enrichment/batch     # Batch enrichment
POST   /api/v1/enrichment/health    # Check TI source health
```

## Project Structure

```
ioc-enrich-system/
├── services/
│   ├── ioc-api-gateway/        # REST API Gateway (Go/Gin)
│   ├── ioc-core/               # Core gRPC service (Go)
│   └── ti-enrichment/          # TI Enrichment gRPC service (Python)
├── shared/
│   ├── go/                     # Generated Go protobuf code
│   └── python/                 # Generated Python protobuf code
├── proto/                      # Protobuf definitions
│   ├── ioc/v1/                 # IoC & Threat service protos
│   └── enrichment/v1/          # Enrichment service protos
├── infrastructure/
│   └── k8s/                    # Kubernetes manifests (Kustomize)
│       ├── base/               # Base manifests
│       └── overlays/           # Environment-specific (dev, production)
├── init/
│   └── init.sql                # Database schema
├── test/
│   ├── unit/                   # Unit tests (Go + Python)
│   ├── integration/            # Integration tests
│   ├── e2e/                    # End-to-end workflow tests
│   └── performance/            # k6 load & stress tests
├── .github/workflows/          # CI pipelines
├── docker-compose.yaml         # Local development
└── Makefile                    # Root build commands
```

## Development

### Generate Protobuf Code

```bash
# Generate both Go and Python
make proto

# Generate Go only
make go

# Generate Python only
make python
```

### Run Tests

```bash
# Unit tests (all services)
make test

# From the test directory:
cd test

# Unit tests
make test-unit

# Integration tests (requires running services)
make test-integration

# Performance tests (requires k6)
make test-performance-load
make test-performance-stress
```

## Kubernetes Deployment

### Local (minikube)

```bash
# Start minikube
minikube start --memory=4096 --cpus=4

# Build images using minikube's Docker
eval $(minikube docker-env)
docker build -t ioc-api-gateway:latest -f services/ioc-api-gateway/Dockerfile .
docker build -t ioc-core:latest -f services/ioc-core/Dockerfile .
docker build -t ti-enrichment:latest -f services/ti-enrichment/Dockerfile .

# Update secrets in infrastructure/k8s/base/secrets.yaml

# Deploy
kubectl apply -k infrastructure/k8s/overlays/dev/

# Check status
kubectl get pods -n ioc-enrich

# Access gateway
minikube service ioc-api-gateway -n ioc-enrich
```

### Production

```bash
kubectl apply -k infrastructure/k8s/overlays/production/
```

## CI Pipeline

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) runs on every push/PR:

```
Lint & Quality ──┐
                 ├──> Build Docker Images ──> Integration Tests
Unit Tests ──────┘           │
                             └──> Push to GHCR (on main/develop)
Security Scan ───────────────────────────────
```

| Stage           | Description                                  |
| --------------- | -------------------------------------------- |
| **Lint**        | golangci-lint (Go), flake8 + black (Python)  |
| **Unit Tests**  | Go race detector, pytest with coverage       |
| **Build**       | Multi-stage Docker builds, GHCR push         |
| **Integration** | Full docker-compose stack with health checks |
| **Security**    | govulncheck (Go), bandit + safety (Python)   |

## Database Schema

The system uses 5 main tables:

- **iocs** — Indicators of Compromise (IP, domain, hash, URL, file path)
- **threats** — Threat actors, campaigns, malware families
- **ioc_relations** — Relationships between IoCs
- **threat_ioc_correlation** — IoC-Threat linkage
- **enrichment_cache** — Cached enrichment results

See [init/init.sql](init/init.sql) for the complete schema.

## Contributors

- **DgHnG36** — [github.com/DgHnG36](https://github.com/DgHnG36)

## License

This project is for educational and research purposes.
