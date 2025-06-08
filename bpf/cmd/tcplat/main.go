package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/metrics"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/options"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
)

func pprint(event tcp.TcpconnLatEvent) error {
	slog.Default().Debug(
		fmt.Sprintf(
			"%s : %s -> %s : %d us | %s -> %s",
			byteutil.CCharSliceToStr(event.Comm[:]),
			byteutil.Ipv4Str(event.SaddrV4),
			byteutil.Ipv4Str(event.DaddrV4),
			event.DeltaUs,
			byteutil.Ipv6Str(event.SaddrV6),
			byteutil.Ipv6Str(event.DaddrV6),
		),
	)
	return nil
}

func main() {
	logger := slog.Default()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	exp, err := otlpmetricgrpc.New(context.TODO(), otlpmetricgrpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	// Create a Meter Provider with the exporter
	mp := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp, metric.WithInterval(5*time.Second))))
	defer func() { _ = mp.Shutdown(context.TODO()) }()

	otel.SetMeterProvider(mp)

	m, err := metrics.NewMetrics(otel.Meter("example.com/tcp"))
	if err != nil {
		panic(err)
	}

	coll := tcp.NewTcpConnLatCollector(logger.With("name", "tcp_lat_collector"), m, options.WithEventCallback(pprint))
	if err := coll.Init(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	if err := coll.Start(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	<-stopper
	logger.Info("stopping")
	coll.Shutdown()
}
