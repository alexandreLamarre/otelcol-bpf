.PHONY: build
.PHONY: run

build:
	@echo "Building otelcol-bpf..."
	cd otelcol && ocb --config=ocb-config.yaml

run:
	@echo "Running otelcol-bpf with..."
	@cat otelcol/config.yaml
	@echo "\n\n"
	sudo ./otelcol/otelcol-bpf --config=otelcol/config.yaml