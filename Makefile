SHELL := /bin/bash
MODULE   = $(shell env GO111MODULE=on $(GO) list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
BIN      = $(CURDIR)/bin
GO      = go
GOPATH = $(shell go env GOPATH)
TIMEOUT = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.DEFAULT_GOAL := test

export GO111MODULE=on
PATH := $(BIN):$(PATH)

# Tools
$(BUILD_DIR):
	@mkdir -p $@

$(BIN):
	@mkdir -p $@
$(BIN)/%: | $(BIN) ; $(info $(M) building $(PACKAGE)…)
	$Q env GOBIN=$(BIN) $(GO) get $(PACKAGE) \
		|| ret=$$?; \
	   git checkout go.mod go.sum; exit $$ret

GOIMPORTS = $(BIN)/goimports
$(BIN)/goimports: PACKAGE=golang.org/x/tools/cmd/goimports

# Tests
TEST_TARGETS := test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test test-bench test-short test-verbose test-race
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. -benchmem ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
test: ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q $(GO) test -timeout $(TIMEOUT)s $(ARGS) ./...

.PHONY: fmt
fmt: | $(GOIMPORTS) ; $(info $(M) running goimports…) @ ## Run goimports on all source files
	$Q $(GOIMPORTS) -local $(MODULE) -w $$(find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: check-fmt
check-fmt: | $(GOIMPORTS) ; $(info $(M) running goimports…) @ ## Check formatting with goimports
	$Q diff -u <(echo -n) <($(GOIMPORTS) -d -local $(MODULE) $$(find . -type f -name '*.go' -not -path "./vendor/*"))

.PHONY: check
check: check-fmt test-race ## Run all checks

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	$Q rm -rf $(BIN)

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo $(VERSION)
