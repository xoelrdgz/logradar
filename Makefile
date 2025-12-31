.PHONY: build run test bench lint clean install deps

APP_NAME := logradar
VERSION := 1.0.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
BINARY_DIR := ./bin

LDFLAGS := -ldflags "-s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(GIT_COMMIT) \
	-X main.BuildTime=$(BUILD_TIME)"
all: deps lint test build
deps:
	@echo "==> Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
build:
	@echo "==> Building $(APP_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(APP_NAME) ./cmd/logradar

build-prod:
	@echo "==> Building $(APP_NAME) for production..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -trimpath -o $(BINARY_DIR)/$(APP_NAME) ./cmd/logradar
run: build
	@echo "==> Running $(APP_NAME)..."
	$(BINARY_DIR)/$(APP_NAME) analyze --demo --demo-rate 5000
run-log: build
	@echo "==> Running $(APP_NAME) with sample.log..."
	$(BINARY_DIR)/$(APP_NAME) analyze --log ./testdata/sample.log
run-notui: build
	@echo "==> Running $(APP_NAME) in console mode..."
	$(BINARY_DIR)/$(APP_NAME) analyze --demo --demo-rate 10000 --no-tui
run-json: build
	@echo "==> Running $(APP_NAME) with JSON output..."
	$(BINARY_DIR)/$(APP_NAME) analyze --demo --demo-rate 1000 --no-tui --json
test:
	@echo "==> Running tests..."
	$(GOTEST) -v -race -cover ./...
test-coverage:
	@echo "==> Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"
bench:
	@echo "==> Running benchmarks..."
	$(GOTEST) -bench=. -benchmem -run=^$$ ./...
lint:
	@echo "==> Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping..."; \
	fi
fmt:
	@echo "==> Formatting code..."
	$(GOFMT) -s -w .
clean:
	@echo "==> Cleaning..."
	@rm -rf $(BINARY_DIR)
	@rm -f coverage.out coverage.html
install: build
	@echo "==> Installing $(APP_NAME)..."
	cp $(BINARY_DIR)/$(APP_NAME) /usr/local/bin/
docker:
	@echo "==> Building Docker image..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(APP_NAME):$(VERSION) \
		-t $(APP_NAME):latest .
docker-run:
	@echo "==> Running $(APP_NAME) in Docker (demo mode)..."
	docker run --rm -it $(APP_NAME):latest analyze --demo --demo-rate 10000

.PHONY: vulncheck sbom audit security-check update-deps fuzz

vulncheck:
	@echo "==> Running vulnerability check..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
sbom:
	@echo "==> Generating SBOM..."
	@mkdir -p $(BINARY_DIR)
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest mod -output $(BINARY_DIR)/sbom.json -json
	@echo "SBOM generated: $(BINARY_DIR)/sbom.json"
audit:
	@echo "==> Auditing dependencies..."
	@echo "--- Checking for outdated dependencies ---"
	$(GOCMD) list -m -u all | grep -v '^\s*$$' | head -20
	@echo ""
	@echo "--- Checking for vulnerabilities ---"
	@$(MAKE) vulncheck
update-deps:
	@echo "==> Checking for dependency updates..."
	$(GOCMD) get -u ./...
	$(GOMOD) tidy
	@echo "Dependencies updated. Run 'make test' to verify."
fuzz:
	@echo "==> Running fuzz tests (5 minutes)..."
	$(GOTEST) -fuzz=Fuzz -fuzztime=5m ./internal/adapters/input/...
	$(GOTEST) -fuzz=Fuzz -fuzztime=5m ./internal/adapters/detection/...
security-check: vulncheck lint test
	@echo "==> Security check complete!"

help:
	@echo "LogRadar - Production-grade HTTP log threat detection"
	@echo ""
	@echo "Usage:"
	@echo "  make deps           Install dependencies"
	@echo "  make build          Build the application"
	@echo "  make build-prod     Build for production (optimized)"
	@echo "  make run            Run with TUI (demo mode)"
	@echo "  make run-log        Run with sample.log"
	@echo "  make run-notui      Run in console mode"
	@echo "  make run-json       Run with JSON output"
	@echo "  make test           Run tests"
	@echo "  make test-coverage  Run tests with coverage report"
	@echo "  make bench          Run benchmarks"
	@echo "  make lint           Run linter"
	@echo "  make fmt            Format code"
	@echo "  make clean          Clean build artifacts"
	@echo "  make install        Install to /usr/local/bin"
	@echo "  make docker         Build Docker image"
	@echo "  make docker-run     Run in Docker (demo)"
	@echo ""
	@echo "Security:"
	@echo "  make vulncheck      Check for known vulnerabilities"
	@echo "  make sbom           Generate Software Bill of Materials"
	@echo "  make audit          Full dependency audit"
	@echo "  make update-deps    Update dependencies"
	@echo "  make fuzz           Run fuzz tests (5 min)"
	@echo "  make security-check Run full security check"

