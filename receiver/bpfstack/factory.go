package bpfstack

import (
	"context"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/internal/sharedcomponent"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpfstack/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithTraces(createTraces, metadata.TracesStability),
		receiver.WithMetrics(createMetrics, metadata.MetricsStability),
		receiver.WithLogs(createLog, metadata.LogsStability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		TargetDiscoveryFreq: 15 * time.Second,
		CollectFreq:         5 * time.Second,
	}
}

// createTraces creates a trace receiver based on provided config.
func createTraces(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	nextConsumer consumer.Traces,
) (receiver.Traces, error) {
	oCfg := cfg.(*Config)
	r, err := receivers.LoadOrStore(
		oCfg,
		func() (*bpfStackReceiver, error) {
			return newBpfStackReceiver(oCfg, &set)
		},
	)
	if err != nil {
		return nil, err
	}

	r.Unwrap().registerTraceConsumer(nextConsumer)
	return r, nil
}

// createMetrics creates a metrics receiver based on provided config.
func createMetrics(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	oCfg := cfg.(*Config)
	r, err := receivers.LoadOrStore(
		oCfg,
		func() (*bpfStackReceiver, error) {
			return newBpfStackReceiver(oCfg, &set)
		},
	)
	if err != nil {
		return nil, err
	}

	r.Unwrap().registerMetricsConsumer(consumer)
	return r, nil
}

// createLog creates a log receiver based on provided config.
func createLog(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	oCfg := cfg.(*Config)
	r, err := receivers.LoadOrStore(
		oCfg,
		func() (*bpfStackReceiver, error) {
			return newBpfStackReceiver(oCfg, &set)
		},
	)
	if err != nil {
		return nil, err
	}

	r.Unwrap().registerLogsConsumer(consumer)
	return r, nil
}

// This is the map of already created OTLP receivers for particular configurations.
// We maintain this map because the Factory is asked trace and metric receivers separately
// when it gets CreateTracesReceiver() and CreateMetricsReceiver() but they must not
// create separate objects, they must use one otlpReceiver object per configuration.
// When the receiver is shutdown it should be removed from this map so the same configuration
// can be recreated successfully.
var receivers = sharedcomponent.NewMap[*Config, *bpfStackReceiver]()
