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
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
)

var (
	metrics *tcp.TCPMetrics
)

func pprint(key tcp.TcpconnlatTrafficKey, val tcp.TcpconnlatTrafficValue) {
	ipv4 := byteutil.EmptyIpv6(byteutil.Ipv6Str(key.SaddrV6))
	if ipv4 {
		slog.Default().With("pid", key.Pid, "comm", byteutil.CCharSliceToStr(key.Name[:])).Debug(
			fmt.Sprintf(
				"%s -> %s: tx : %d, rx : %d",
				byteutil.Ipv4Str(key.SaddrV4),
				byteutil.Ipv4Str(key.DaddrV4),
				val.Tx, val.Rx,
			),
		)
	} else {
		slog.Default().With("pid", key.Pid, "comm", byteutil.CCharSliceToStr(key.Name[:])).Debug(
			fmt.Sprintf(
				"%s -> %s: tx : %d, rx : %d",
				byteutil.Ipv6Str(key.SaddrV6),
				byteutil.Ipv6Str(key.DaddrV6),
				val.Tx, val.Rx,
			),
		)
	}

	metrics.ConnStatsCallback(key, val)
}

func main() {
	logger := slog.Default()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	exp, err := otlpmetricgrpc.New(context.TODO(), otlpmetricgrpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	mp := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp, metric.WithInterval(5*time.Second))))
	defer func() { _ = mp.Shutdown(context.TODO()) }()

	otel.SetMeterProvider(mp)

	metricss, err := tcp.NewTcpMetrics(context.Background(), otel.Meter("tcpConnLat"))
	if err != nil {
		panic(err)
	}
	metrics = metricss

	coll := tcp.NewTcpStatsCollector(logger.With("name", "tcp_stats_collector"), 2*time.Second, pprint)
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
