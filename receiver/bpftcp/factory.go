package bpftcp

import (
	"context"

	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetrics, metadata.MetricsStability),
	)
}
func createDefaultConfig() component.Config {
	return &Config{}
}

func createMetrics(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	recv, err := newBpfTcpReceiver(set, consumer)
	return recv, err
}
