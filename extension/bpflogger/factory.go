package bpflogger

import (
	"context"

	"github.com/alexandreLamarre/otelcol-bpf/extension/bpflogger/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createExtension(_ context.Context, ext extension.Settings, config component.Config) (extension.Extension, error) {
	return newExtension(config.(*Config), ext.Logger.Named("bpf_logger"))
}

func createDefaultConfig() component.Config {
	return &Config{
		TracePipe: "",
	}
}
