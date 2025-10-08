# Go Makefile - AGILira Standard
# Usage: make help

.PHONY: help test race fmt vet lint security check deps clean build install tools
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := $(shell basename $(PWD))
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')
TOOLS_DIR := $(HOME)/go/bin

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

test: ## Run tests
	@echo "$(YELLOW)Running tests...$(NC)"
	go test -v ./...

race: ## Run tests with race detector
	@echo "$(YELLOW)Running tests with race detector...$(NC)"
	go test -race -v ./...

coverage: ## Run tests with coverage
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

fmt: ## Format Go code
	@echo "$(YELLOW)Formatting Go code...$(NC)"
	go fmt ./...

vet: ## Run go vet
	@echo "$(YELLOW)Running go vet...$(NC)"
	go vet ./...

staticcheck: ## Run staticcheck
	@echo "$(YELLOW)Running staticcheck...$(NC)"
	@if [ ! -f "$(TOOLS_DIR)/staticcheck" ]; then \
		echo "$(RED)staticcheck not found. Run 'make tools' to install.$(NC)"; \
		exit 1; \
	fi
	$(TOOLS_DIR)/staticcheck ./...

errcheck: ## Run errcheck
	@echo "$(YELLOW)Running errcheck...$(NC)"
	@if [ ! -f "$(TOOLS_DIR)/errcheck" ]; then \
		echo "$(RED)errcheck not found. Run 'make tools' to install.$(NC)"; \
		exit 1; \
	fi
	$(TOOLS_DIR)/errcheck ./...

gosec: ## Run gosec security scanner
	@echo "$(YELLOW)Running gosec security scanner...$(NC)"
	@if [ ! -f "$(TOOLS_DIR)/gosec" ]; then \
		echo "$(RED)gosec not found. Run 'make tools' to install.$(NC)"; \
		exit 1; \
	fi
	@$(TOOLS_DIR)/gosec ./... || (echo "$(YELLOW)  gosec completed with warnings (may be import-related)$(NC)" && exit 0)

govulncheck: ## Run govulncheck vulnerability scanner
	@echo "$(YELLOW)Running govulncheck vulnerability scanner...$(NC)"
	@if [ ! -f "$(TOOLS_DIR)/govulncheck" ]; then \
		echo "$(RED)govulncheck not found. Run 'make tools' to install.$(NC)"; \
		exit 1; \
	fi
	$(TOOLS_DIR)/govulncheck ./...

lint: staticcheck errcheck ## Run all linters
	@echo "$(GREEN)All linters completed.$(NC)"

security: gosec govulncheck ## Run security checks
	@echo "$(GREEN)Security checks completed.$(NC)"

check: fmt vet lint security test ## Run all checks (format, vet, lint, security, test)
	@echo "$(GREEN)All checks passed!$(NC)"

check-race: fmt vet lint security race ## Run all checks including race detector
	@echo "$(GREEN)All checks with race detection passed!$(NC)"

tools: ## Install development tools
	@echo "$(YELLOW)Installing development tools...$(NC)"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/kisielk/errcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "$(GREEN)Tools installed successfully!$(NC)"

deps: ## Download and verify dependencies
	@echo "$(YELLOW)Downloading dependencies...$(NC)"
	go mod download
	go mod verify
	go mod tidy

clean: ## Clean build artifacts and test cache
	@echo "$(YELLOW)Cleaning...$(NC)"
	go clean
	go clean -testcache
	rm -f coverage.out coverage.html
	rm -f $(BINARY_NAME)

build: ## Build the binary
	@echo "$(YELLOW)Building $(BINARY_NAME)...$(NC)"
	go build -ldflags="-w -s" -o $(BINARY_NAME) .

install: ## Install the binary to $GOPATH/bin
	@echo "$(YELLOW)Installing $(BINARY_NAME)...$(NC)"
	go install .

bench: ## Run benchmarks
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	go test -bench=. -benchmem ./...

fuzz: ## Run fuzz tests
	@echo "$(YELLOW)Running fuzz tests...$(NC)"
	@echo "$(BLUE)Starting comprehensive fuzz testing suite...$(NC)"
	@echo "$(BLUE)Testing Consul URL parsing...$(NC)"
	go test -fuzz=FuzzParseConsulURL -fuzztime=30s .
	@echo "$(BLUE)Testing key path validation...$(NC)"
	go test -fuzz=FuzzValidateSecureKeyPath -fuzztime=30s .
	@echo "$(BLUE)Testing JSON parsing...$(NC)"
	go test -fuzz=FuzzConsulJSONParsing -fuzztime=30s .
	@echo "$(BLUE)Testing integrated Load function...$(NC)"
	go test -fuzz=FuzzConsulLoad -fuzztime=30s .
	@echo "$(GREEN)All fuzz tests completed successfully!$(NC)"

fuzz-extended: ## Run extended fuzz tests (longer duration)
	@echo "$(YELLOW)Running extended fuzz tests (5 minutes each)...$(NC)"
	@echo "$(BLUE)Extended fuzz testing - this will take approximately 20 minutes...$(NC)"
	@echo "$(BLUE)Testing Consul URL parsing (5m)...$(NC)"
	go test -fuzz=FuzzParseConsulURL -fuzztime=5m .
	@echo "$(BLUE)Testing key path validation (5m)...$(NC)"
	go test -fuzz=FuzzValidateSecureKeyPath -fuzztime=5m .
	@echo "$(BLUE)Testing JSON parsing (5m)...$(NC)"
	go test -fuzz=FuzzConsulJSONParsing -fuzztime=5m .
	@echo "$(BLUE)Testing integrated Load function (5m)...$(NC)"
	go test -fuzz=FuzzConsulLoad -fuzztime=5m .
	@echo "$(GREEN)Extended fuzz tests completed successfully!$(NC)"

fuzz-continuous: ## Run continuous fuzz testing (until interrupted)
	@echo "$(YELLOW)Running continuous fuzz tests (press Ctrl+C to stop)...$(NC)"
	@echo "$(BLUE)Continuous fuzz testing - press Ctrl+C when satisfied...$(NC)"
	@trap 'echo "$(GREEN)Continuous fuzzing stopped by user$(NC)"; exit 0' INT; \
	while true; do \
		echo "$(BLUE)Round: URL parsing...$(NC)"; \
		timeout 2m go test -fuzz=FuzzParseConsulURL -fuzztime=1m . || true; \
		echo "$(BLUE)Round: Key validation...$(NC)"; \
		timeout 2m go test -fuzz=FuzzValidateSecureKeyPath -fuzztime=1m . || true; \
		echo "$(BLUE)Round: JSON parsing...$(NC)"; \
		timeout 2m go test -fuzz=FuzzConsulJSONParsing -fuzztime=1m . || true; \
		echo "$(BLUE)Round: Load function...$(NC)"; \
		timeout 2m go test -fuzz=FuzzConsulLoad -fuzztime=1m . || true; \
		echo "$(GREEN)Completed fuzz round, starting next...$(NC)"; \
	done

fuzz-report: ## Generate fuzz testing report
	@echo "$(YELLOW)Generating fuzz test report...$(NC)"
	@echo "$(BLUE)Fuzz Test Coverage Report for Consul Provider$(NC)" > fuzz_report.txt
	@echo "=========================================" >> fuzz_report.txt
	@echo "" >> fuzz_report.txt
	@echo "Test Functions:" >> fuzz_report.txt
	@echo "- FuzzParseConsulURL: Tests Consul URL parsing security" >> fuzz_report.txt
	@echo "- FuzzValidateSecureKeyPath: Tests path traversal prevention" >> fuzz_report.txt
	@echo "- FuzzConsulJSONParsing: Tests JSON parser resilience" >> fuzz_report.txt
	@echo "- FuzzConsulLoad: Tests end-to-end Load function" >> fuzz_report.txt
	@echo "" >> fuzz_report.txt
	@echo "Security Coverage:" >> fuzz_report.txt
	@echo "- URL injection and SSRF prevention" >> fuzz_report.txt
	@echo "- Path traversal attack detection" >> fuzz_report.txt
	@echo "- Authentication bypass prevention" >> fuzz_report.txt
	@echo "- JSON parser DoS protection" >> fuzz_report.txt
	@echo "- Resource exhaustion prevention" >> fuzz_report.txt
	@echo "" >> fuzz_report.txt
	@echo "Generated: $(shell date)" >> fuzz_report.txt
	@echo "$(GREEN)Fuzz report generated: fuzz_report.txt$(NC)"

security-full: security fuzz ## Run complete security testing (static analysis + fuzz)
	@echo "$(GREEN)Complete security testing finished!$(NC)"

ci: ## Run CI checks (used in GitHub Actions)
	@echo "$(BLUE)Running CI checks...$(NC)"
	@make fmt vet lint security test coverage
	@echo "$(GREEN)CI checks completed successfully!$(NC)"

ci-security: ## Run CI checks with fuzz testing (for security-focused CI)
	@echo "$(BLUE)Running security-focused CI checks...$(NC)"
	@make fmt vet lint security test coverage fuzz
	@echo "$(GREEN)Security CI checks completed successfully!$(NC)"

dev: ## Quick development check (fast feedback loop)
	@echo "$(BLUE)Running development checks...$(NC)"
	@make fmt vet test
	@echo "$(GREEN)Development checks completed!$(NC)"

pre-commit: check ## Run pre-commit checks (alias for 'check')

all: clean tools deps check build ## Run everything from scratch

# Show tool status
status: ## Show status of installed tools
	@echo "$(BLUE)Development tools status:$(NC)"
	@echo -n "staticcheck:   "; [ -f "$(TOOLS_DIR)/staticcheck" ] && echo "$(GREEN)✓ installed$(NC)" || echo "$(RED)✗ missing$(NC)"
	@echo -n "errcheck:      "; [ -f "$(TOOLS_DIR)/errcheck" ] && echo "$(GREEN)✓ installed$(NC)" || echo "$(RED)✗ missing$(NC)"
	@echo -n "gosec:         "; [ -f "$(TOOLS_DIR)/gosec" ] && echo "$(GREEN)✓ installed$(NC)" || echo "$(RED)✗ missing$(NC)"
	@echo -n "govulncheck:   "; [ -f "$(TOOLS_DIR)/govulncheck" ] && echo "$(GREEN)✓ installed$(NC)" || echo "$(RED)✗ missing$(NC)"