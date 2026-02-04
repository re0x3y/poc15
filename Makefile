.PHONY: help build test run clean deps lint config

help: ## Display this help message
	@echo "POC 15 - Beeldbeschikbaarheid (Image Availability)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

deps: ## Install dependencies
	go mod download
	go mod tidy

config: ## Create config.yaml from example
	@if [ ! -f config.yaml ]; then \
		cp config.example.yaml config.yaml; \
		echo "✓ Created config.yaml from config.example.yaml"; \
	else \
		echo "config.yaml already exists"; \
	fi

build: deps ## Build all binaries
	@echo "Building POC 15 binaries..."
	@mkdir -p bin
	go build -o bin/poc15-server ./cmd/server
	@echo "✓ Build complete"

test: ## Run tests
	@echo "Running tests..."
	go test -v ./...

run: build config ## Run HTTP server
	@echo "Running HTTP server..."
	./bin/poc15-server

lint: ## Run linters
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	go clean
	@echo "✓ Clean complete"

format: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@echo "✓ Format complete"

coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

.DEFAULT_GOAL := help
