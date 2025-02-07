include ./Makefile.Common

.PHONY: build
.PHONY: run
CONFIG_TARGET ?= ./cmd/otelcol/config.yaml

EXCLUDE_PATHS := ./cmd|^./bpf
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


LIBBPF_VERSION=0.6.1
LIBBPF_PREFIX="https://raw.githubusercontent.com/libbpf/libbpf/v$(LIBBPF_VERSION)"

.PHONY: get-headers
headers: get-libbpf-headers get-vmlinux-header

.PHONY: get-libbpf-headers
get-libbpf-headers:
	cd bpf/include && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_endian.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_helper_defs.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_helpers.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_tracing.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_core_read.h

.PHONY: get-vmlinux-header
get-vmlinux-header:
	cd bpf/include && \
		curl -o vmlinux.h https://raw.githubusercontent.com/iovisor/bcc/v0.27.0/libbpf-tools/x86/vmlinux_518.h

.PHONY: clean
clean:
	rm -rf libbpf/*.h vmlinux/*.h
