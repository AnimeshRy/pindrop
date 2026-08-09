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
#
# This applies to anything that resolves the stdlib through go/packages, not just
# the driver: golangci-lint's typecheck reads GOROOT too and fails identically,
# except that it reports the mismatch against an unrelated import (`could not
# import errors`), which sends you looking in the wrong place. Prefix every
# Go-aware tool with $(NO_GOROOT); never invoke one bare.
NO_GOROOT := env -u GOROOT
GO        := $(NO_GOROOT) go

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
OSV_SCANNER_VERSION   := v2.4.0
OPENGREP_VERSION      := v1.26.0
# Must match the version internal/scan/trufflehog/testdata/report.jsonl was
# captured from — see that directory's README. Bump both together.
TRUFFLEHOG_VERSION    := v3.96.0

# golangci-lint refuses to analyze a module whose `go` directive is newer than
# the Go release it was itself built with, and its published module targets an
# older Go than we do. Forcing the toolchain makes the installed binary match.
GO_TOOLCHAIN := go1.26.5

# Tool resolution: a mise-managed copy wins, otherwise ./bin gets a pinned one
# installed on demand. mise is optional — every target works without it.
#
# `mise which` is used rather than `command -v` on purpose: it only reports
# tools mise itself manages, so a system-wide golangci-lint v1 on PATH (which
# cannot read our v2 config) is never picked up. The $(wildcard) guard keeps the
# result empty until the binary actually exists, so make falls back to the ./bin
# install rule instead of failing on a path with no rule to build it.
MISE      := $(shell command -v mise 2>/dev/null)
mise_tool = $(if $(MISE),$(wildcard $(shell $(MISE) which $(1) 2>/dev/null)))

# These hold bare paths, because they are also used as target prerequisites.
# Prefix $(NO_GOROOT) when running them — see the note above.
GOLANGCI_LINT := $(or $(call mise_tool,golangci-lint),$(BIN)/golangci-lint)
GOFUMPT       := $(or $(call mise_tool,gofumpt),$(BIN)/gofumpt)
TRIVY         := $(or $(call mise_tool,trivy),$(BIN)/trivy)
OSV_SCANNER   := $(or $(call mise_tool,osv-scanner),$(BIN)/osv-scanner)
OPENGREP      := $(or $(call mise_tool,opengrep),$(BIN)/opengrep)
TRUFFLEHOG    := $(or $(call mise_tool,trufflehog),$(BIN)/trufflehog)

PNPM := pnpm --dir web

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Setup

.PHONY: setup
setup: tools trivy osv-scanner opengrep trufflehog web-install ## Install everything needed to build and run
	@echo
	@echo "Setup complete. Try: ./bin/pindrop scan ."

.PHONY: tools
tools: $(GOLANGCI_LINT) $(GOFUMPT) ## Install pinned Go tools into ./bin

.PHONY: trivy
trivy: $(TRIVY) ## Install the pinned Trivy release into ./bin

.PHONY: osv-scanner
osv-scanner: $(OSV_SCANNER) ## Install the pinned OSV-Scanner release into ./bin

.PHONY: opengrep
opengrep: $(OPENGREP) ## Install the pinned Opengrep release into ./bin

.PHONY: trufflehog
trufflehog: $(TRUFFLEHOG) ## Install the pinned TruffleHog release into ./bin

# pindrop looks for trivy on PATH and then beside its own binary, so installing
# here is enough — ./bin does not need to be on PATH.
# Keyed on $(BIN)/... rather than the resolved variable: when mise provides the
# tool, its path already exists and needs no rule.
$(BIN)/trivy:
	@mkdir -p $(BIN)
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
		| sh -s -- -b $(CURDIR)/$(BIN) $(TRIVY_VERSION)
	@$(BIN)/trivy --version | head -1

$(BIN)/golangci-lint:
	@mkdir -p $(BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/$(BIN) \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(BIN)/gofumpt:
	@mkdir -p $(BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/$(BIN) \
		$(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

# Installed via `go install` rather than the release tarball: it is a Go program,
# so this needs no extra download path, and the version is pinned either way.
$(BIN)/osv-scanner:
	@mkdir -p $(BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/$(BIN) \
		$(GO) install github.com/google/osv-scanner/v2/cmd/osv-scanner@$(OSV_SCANNER_VERSION)
	@$(BIN)/osv-scanner --version | head -1

# Opengrep publishes a single-file binary per platform rather than an install
# script we can pin, so the asset name is derived from uname.
#
# Download the `opengrep_*` asset, never `opengrep-core_*`: the latter is the
# internal OCaml engine only, and the single file already embeds it.
$(BIN)/opengrep:
	@mkdir -p $(BIN)
	@set -euo pipefail; \
	case "$$(uname -s)-$$(uname -m)" in \
	  Darwin-arm64|Darwin-aarch64) asset=opengrep_osx_arm64 ;; \
	  Darwin-x86_64)               asset=opengrep_osx_x86 ;; \
	  Linux-x86_64)                asset=opengrep_manylinux_x86 ;; \
	  Linux-aarch64|Linux-arm64)   asset=opengrep_manylinux_aarch64 ;; \
	  *) echo "No Opengrep release asset for $$(uname -sm)."; \
	     echo "Install it manually, then use --opengrep-binary. Skipping."; exit 0 ;; \
	esac; \
	echo "Downloading $$asset $(OPENGREP_VERSION)"; \
	curl -sfL -o $(BIN)/opengrep \
	  https://github.com/opengrep/opengrep/releases/download/$(OPENGREP_VERSION)/$$asset; \
	chmod +x $(BIN)/opengrep
	@$(BIN)/opengrep --version | head -1

# TruffleHog ships an install script with the same `-b BINDIR <TAG>` interface as
# Trivy's, so this is the Trivy rule with the URL changed.
#
# Deliberately not `go install`, even though TruffleHog is a Go program and
# osv-scanner above is installed that way: TruffleHog is AGPL-3.0. Keeping it out
# of the module graph entirely means nobody can later move it into a tools file
# and place this codebase under AGPL. See docs/architecture/scanners.md.
$(BIN)/trufflehog:
	@mkdir -p $(BIN)
	curl -sfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
		| sh -s -- -b $(CURDIR)/$(BIN) $(TRUFFLEHOG_VERSION)
	@$(BIN)/trufflehog --version 2>&1 | head -1

# Regenerates the digests `pindrop setup` verifies its downloads against.
#
# Run this after changing a scanner version, and review the diff carefully: those
# digests are the only thing standing between a modified upstream release and a
# binary Pindrop hands to the user. Three of the four tools are cross-checked
# against upstream's own published checksum file; Opengrep publishes none, so its
# digest is trust-on-first-pin and the generator prints a cosign command for
# verifying it by hand. See docs/decisions/0010-managed-scanner-installation.md.
#
# The Makefile's *_VERSION pins above and the manifest must agree — a test in
# internal/toolinstall asserts it, so a forgotten regeneration fails `make test`
# rather than a user's install.
.PHONY: manifest
manifest: ## Regenerate the pinned scanner manifest and its checksums
	$(GO) run ./internal/toolinstall/genmanifest

.PHONY: manifest-check
manifest-check: ## Verify the committed manifest still matches upstream
	$(GO) run ./internal/toolinstall/genmanifest -check

.PHONY: mise
mise: ## Install the optional mise-managed toolchain (see mise.toml)
	@test -n "$(MISE)" \
		|| { echo "mise is not installed. It is optional — 'make setup' works without it."; \
		     echo "To use it: https://mise.jdx.dev/getting-started.html"; exit 1; }
	$(MISE) install
	@echo
	@echo "Installed. Tool paths resolve at make startup, so re-run 'make setup' —"
	@echo "it will now skip anything mise provides."

.PHONY: web-install
web-install: ## Install frontend dependencies
	@# corepack would install a second pnpm shim over the mise-managed one.
	$(if $(call mise_tool,pnpm),@echo "pnpm provided by mise; skipping corepack",corepack enable pnpm)
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
	$(NO_GOROOT) $(GOLANGCI_LINT) run ./...

.PHONY: lint-web
lint-web: ## Lint and typecheck the frontend
	$(PNPM) lint
	$(PNPM) typecheck

.PHONY: fmt
fmt: $(GOLANGCI_LINT) ## Format Go and frontend code
	$(NO_GOROOT) $(GOLANGCI_LINT) fmt ./...
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

# Exercises the secrets adapter, which `run-scan` cannot: the bundled fixture
# deliberately contains no detectable credential, so TruffleHog reports 0 against
# it. See testdata/vulnerable-app/README.md for why that is the right trade.
#
# The credentials are generated at run time into a temporary directory outside the
# repository and removed on exit. They are assembled from fragments rather than
# written as literals for a specific reason: a complete credential-shaped string in
# any tracked file — including this Makefile — would be found by Pindrop's own scan
# of itself, which is exactly the outcome the fixture README refuses. "AKIA" and
# "ghp_" on their own match nothing.
#
# Nothing here is or ever was a real credential, and no verification is performed,
# so nothing leaves the machine. Never add --verify-secrets to this target.
.PHONY: run-scan-secrets
run-scan-secrets: build-go ## Scan a throwaway credential directory (the secrets path)
	@set -eu; \
	dir=$$(mktemp -d); \
	trap 'rm -rf "$$dir"' EXIT INT TERM; \
	rand() { LC_ALL=C tr -dc "$$1" </dev/urandom 2>/dev/null | head -c "$$2" || true; }; \
	{ \
	  printf 'AWS_ACCESS_KEY_ID=%s%s\n'  'AKIA' "$$(rand 'A-Z0-9' 16)"; \
	  printf 'AWS_SECRET_ACCESS_KEY=%s\n'       "$$(rand 'A-Za-z0-9' 40)"; \
	  printf 'GITHUB_TOKEN=%s%s\n'       'ghp_' "$$(rand 'A-Za-z0-9' 36)"; \
	  printf 'DATABASE_URL=postgres://svc:%s@db.example.invalid:5432/app\n' \
	                                            "$$(rand 'A-Za-z0-9' 16)"; \
	} >"$$dir/.env"; \
	openssl genrsa -out "$$dir/id_rsa" 2048 2>/dev/null || \
	  echo "note: openssl unavailable, skipping the PrivateKey case"; \
	echo "Throwaway credentials in $$dir (removed on exit). Nothing here is real."; \
	echo; \
	./$(BINARY) scan "$$dir"

.PHONY: run-serve
run-serve: build ## Scan the sample app and serve the dashboard
	./$(BINARY) scan ./testdata/vulnerable-app --format json --out .pindrop/report.json
	./$(BINARY) serve

##@ Cleanup

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf coverage.out .pindrop web/dist/assets web/dist/index.html
	rm -f $(BINARY)
	@echo "Kept ./bin tooling (scanners, golangci-lint). Use 'make clean-tools' to remove it."

.PHONY: clean-tools
clean-tools: ## Remove installed Go tools and scanner binaries from ./bin
	rm -rf $(BIN)

.PHONY: clean-all
clean-all: clean clean-tools ## Also remove tooling and frontend dependencies
	rm -rf web/node_modules
