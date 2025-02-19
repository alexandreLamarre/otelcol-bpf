package bpftcp

import (
	"context"
	"log/slog"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver"
)

type metricsReceiver struct {
	statsColl *tcp.TcpStatsCollector
	latColl   *tcp.TcpConnLatCollector
}

func NewMetricsReceiver(set component.TelemetrySettings) (*metricsReceiver, error) {
	metrics, err := tcp.NewTcpMetrics(context.Background(), set.MeterProvider.Meter("github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp"))
	if err != nil {
		return nil, err
	}
	collStats := tcp.NewTcpStatsCollector(slog.Default(), 1, metrics.ConnStatsCallback)
	if err := collStats.Init(); err != nil {
		return nil, err
	}

	collLat := tcp.NewTcpConnLatCollector(slog.Default(), metrics.ConnLatCallback)
	if err := collLat.Init(); err != nil {
		return nil, err
	}

	return &metricsReceiver{
		statsColl: collStats,
		latColl:   collLat,
	}, nil
}

var _ receiver.Metrics = (*metricsReceiver)(nil)

func (b *metricsReceiver) Start(ctx context.Context, _ component.Host) error {
	if err := b.statsColl.Start(); err != nil {
		return err
	}
	if err := b.latColl.Start(); err != nil {
		return err
	}
	return nil
}

func (b *metricsReceiver) Shutdown(context.Context) error {
	b.statsColl.Shutdown()
	b.latColl.Shutdown()
	return nil
}
