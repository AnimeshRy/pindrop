# Pindrop developer tasks.
#
# Tool versions are pinned here so local runs and CI cannot drift. Go tools are
# installed into ./bin rather than declared in go.mod: `go install pkg@version`
# resolves in an isolated module context, which keeps golangci-lint's very large
# dependency tree out of our own go.sum.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Go is invoked through this variable, never as a bare `go`.
#
# An exported GOROOT breaks every build the moment GOTOOLCHAIN switches
# toolchains: the go driver re-execs into the newer toolchain while GOROOT still
# points at the older install's precompiled stdlib, producing
# `compile: version "goX" does not match go tool version "goY"`. Modern Go
# detects its own GOROOT, so clearing it is always correct here.
GO := env -u GOROOT go

BIN          := bin
BINARY       := $(BIN)/pindrop
MODULE       := github.com/AnimeshRy/pindrop
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS      := -s -w -X $(MODULE)/internal/buildinfo.version=$(VERSION)

GOLANGCI_LINT_VERSION := v2.12.2
GOFUMPT_VERSION       := v0.11.0
# Pinned rather than tracking latest: Trivy's release channel was compromised
# twice in 2026, and its report schema is a contract we parse.
TRIVY_VERSION         := v0.72.0

# golangci-lint refuses to analyze a module whose `go` directive is newer than
# the Go release it was itself built with, and its published module targets an
# older Go than we do. Forcing the toolchain makes the installed binary match.
GO_TOOLCHAIN := go1.26.5

GOLANGCI_LINT := $(BIN)/golangci-lint
GOFUMPT       := $(BIN)/gofumpt
TRIVY         := $(BIN)/trivy

PNPM := pnpm --dir web

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Setup

.PHONY: setup
setup: tools trivy web-install ## Install everything needed to build and run
	@echo
	@echo "Setup complete. Try: ./bin/pindrop scan ."

.PHONY: tools
tools: $(GOLANGCI_LINT) $(GOFUMPT) ## Install pinned Go tools into ./bin

.PHONY: trivy
trivy: $(TRIVY) ## Install the pinned Trivy release into ./bin

# pindrop looks for trivy on PATH and then beside its own binary, so installing
# here is enough — ./bin does not need to be on PATH.
$(TRIVY):
	@mkdir -p $(BIN)
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
		| sh -s -- -b $(CURDIR)/$(BIN) $(TRIVY_VERSION)
	@$(TRIVY) --version | head -1

$(GOLANGCI_LINT):
	@mkdir -p $(BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/$(BIN) \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOFUMPT):
	@mkdir -p $(BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/$(BIN) \
		$(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

.PHONY: web-install
web-install: ## Install frontend dependencies
	corepack enable pnpm
	$(PNPM) install --frozen-lockfile

##@ Build

.PHONY: build
build: web $(BINARY) ## Build the full binary with the dashboard embedded

.PHONY: build-go
build-go: $(BINARY) ## Build the Go binary only, using whatever is in web/dist

.PHONY: $(BINARY)
$(BINARY):
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/pindrop

.PHONY: web
web: ## Build the frontend into web/dist
	$(PNPM) build

.PHONY: dev
dev: ## Run the frontend dev server against a locally running API
	$(PNPM) dev

##@ Quality

.PHONY: test
test: ## Run Go tests with the race detector
	$(GO) test -race ./...

.PHONY: test-cover
test-cover: ## Run tests and report coverage
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: lint-go lint-web ## Run all linters

.PHONY: lint-go
lint-go: $(GOLANGCI_LINT) ## Lint Go code
	$(GOLANGCI_LINT) run ./...

.PHONY: lint-web
lint-web: ## Lint and typecheck the frontend
	$(PNPM) lint
	$(PNPM) typecheck

.PHONY: fmt
fmt: $(GOLANGCI_LINT) ## Format Go and frontend code
	$(GOLANGCI_LINT) fmt ./...
	$(PNPM) format

.PHONY: verify
verify: ## Check that generated and formatted files are up to date
	$(GO) mod tidy -diff
	$(MAKE) fmt
	@git diff --exit-code || { echo "Formatting produced changes; commit them."; exit 1; }

.PHONY: check
check: lint test ## Run linters and tests

##@ Run

.PHONY: run-scan
run-scan: build-go ## Scan the sample vulnerable app
	./$(BINARY) scan ./testdata/vulnerable-app

.PHONY: run-serve
run-serve: build ## Scan the sample app and serve the dashboard
	./$(BINARY) scan ./testdata/vulnerable-app --format json --out .pindrop/report.json
	./$(BINARY) serve

##@ Cleanup

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf coverage.out .pindrop web/dist/assets web/dist/index.html
	rm -f $(BINARY)
	@echo "Kept ./bin tooling (trivy, golangci-lint). Use 'make clean-tools' to remove it."

.PHONY: clean-tools
clean-tools: ## Remove installed Go tools and Trivy from ./bin
	rm -rf $(BIN)

.PHONY: clean-all
clean-all: clean clean-tools ## Also remove tooling and frontend dependencies
	rm -rf web/node_modules
