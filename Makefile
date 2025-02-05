include ./Makefile.Common

.PHONY: build
.PHONY: run
CONFIG_TARGET ?= ./cmd/otelcol/config.yaml

EXCLUDE_PATHS="./cmd"
# ALL_MODULES includes ./* dirs (excludes . dir)
ALL_MODULES := $(shell find . -type f -name "go.mod" -exec dirname {} \; | sort | grep -E '^./' | grep -v -E "$(EXCLUDE_PATHS)" )
# Append root module to all modules
GOMODULES = $(ALL_MODULES) $(PWD)

# Define a delegation target for each module
.PHONY: $(GOMODULES)
$(GOMODULES):
	@echo "Running target '$(TARGET)' in module '$@'"
	$(MAKE) -C $@ $(TARGET)

# Triggers each module's delegation target
.PHONY: for-all-target
for-all-target: $(GOMODULES)

.PHONY: gogenerate
gogenerate:
	@$(MAKE) for-all-target TARGET="generate"

.PHONY: gotidy
gotidy:
	@$(MAKE) for-all-target TARGET="tidy"

build:
	@echo "Building otelcol-bpf..."
	cd ./cmd/otelcol && ocb --config=ocb-config.yaml

run:
	@echo "Running otelcol-bpf with..."
	@cat ./cmd/otelcol/config.yaml | grep -E '^[[:space:]]*#' -v
	sudo ./cmd/otelcol/otelcol-bpf --config=$(CONFIG_TARGET)
