package bpfstack

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

type bpfStackReceiver struct {
	cfg *Config

	nextTraces  consumer.Traces
	nextMetrics consumer.Metrics
	nextLogs    consumer.Logs

	settings *receiver.CreateSettings
}

func newBpfStackReceiver(cfg *Config, set *receiver.CreateSettings) (*bpfStackReceiver, error) {
	// TODO
	return &bpfStackReceiver{
		cfg:      cfg,
		settings: set,
	}, nil
}

func (b *bpfStackReceiver) Start(ctx context.Context, host component.Host) error {
	// TODO
	return nil
}

func (b *bpfStackReceiver) Shutdown(ctx context.Context) error {
	// TODO
	return nil
}

var _ component.Component = (*bpfStackReceiver)(nil)

func (r *bpfStackReceiver) registerTraceConsumer(tc consumer.Traces) {
	r.nextTraces = tc
}

func (r *bpfStackReceiver) registerMetricsConsumer(mc consumer.Metrics) {
	r.nextMetrics = mc
}

func (r *bpfStackReceiver) registerLogsConsumer(lc consumer.Logs) {
	r.nextLogs = lc
}
