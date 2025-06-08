package tcp_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/metrics"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
}

func TestTcpConnStats(t *testing.T) {
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	defer meterProvider.Shutdown(context.Background())
	otel.SetMeterProvider(meterProvider)
	meter := otel.Meter("example.com/tcp")
	m, err := metrics.NewMetrics(meter)

	assert.NoError(t, err)
	assert.NotNil(t, m)

	coll := tcp.NewTcpStatsCollector(slog.Default(), 1*time.Second, m)

	err = coll.Init()
	assert.NoError(t, err)
	defer coll.Shutdown()
	err = coll.Start()
	assert.NoError(t, err)
	// TODO : design tests with reproducible data
	assert.Eventually(t, func() bool {
		rm := &metricdata.ResourceMetrics{}
		reader.Collect(context.TODO(), rm)
		metricLen := 0
		for _, sMetric := range rm.ScopeMetrics {
			metricLen += len(sMetric.Metrics)
		}
		return metricLen > 0
	}, 10*time.Second, 1*time.Second)
}

func TestTcpConnLat(t *testing.T) {
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	defer meterProvider.Shutdown(context.Background())
	otel.SetMeterProvider(meterProvider)
	meter := otel.Meter("example.com/tcp")

	m, err := metrics.NewMetrics(meter)
	assert.NoError(t, err)
	assert.NotNil(t, m)

	coll := tcp.NewTcpConnLatCollector(slog.Default(), m)

	err = coll.Init()
	assert.NoError(t, err)
	defer coll.Shutdown()
	err = coll.Start()
	assert.NoError(t, err)
	// TODO : design tests with reproducible data
	assert.Eventually(t, func() bool {
		rm := &metricdata.ResourceMetrics{}
		reader.Collect(context.TODO(), rm)
		metricLen := 0
		for _, sMetric := range rm.ScopeMetrics {
			metricLen += len(sMetric.Metrics)
		}
		return metricLen > 0
	}, 10*time.Second, 1*time.Second)
}
