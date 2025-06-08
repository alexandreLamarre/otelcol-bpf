package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/metrics"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/options"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	promsdk "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	expprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func promDriver(registry *promsdk.Registry, name string) metric.Meter {
	exporter, err := expprom.New(
		expprom.WithRegisterer(registry),
	)
	if err != nil {
		panic(err)
	}
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
	)

	return meterProvider.Meter(name)
}

func otlpDriver(name string) metric.Meter {
	exp, err := otlpmetricgrpc.New(context.TODO(), otlpmetricgrpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(5*time.Second)),
		),
	)
	return mp.Meter(name)
}

func pprint(pair tcp.TcpconnlatTrafficPair) error {
	key := pair.Key
	val := pair.Val
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
	return nil
}

func main() {
	logger := slog.Default()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// exp, err := otlpmetricgrpc.New(context.TODO(), otlpmetricgrpc.WithInsecure())
	// if err != nil {
	// 	panic(err)
	// }

	// mp := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp, metric.WithInterval(5*time.Second))))
	// defer func() { _ = mp.Shutdown(context.TODO()) }()

	// otel.SetMeterProvider(mp)
	registry := promsdk.NewRegistry()
	meter := promDriver(registry, "tcp_stats_collector")
	m, err := metrics.NewMetrics(meter)
	if err != nil {
		logger.Error("failed to create TCP metrics", slog.String("error", err.Error()))
		os.Exit(1)
	}

	coll := tcp.NewTcpStatsCollector(logger.With("name", "tcp_stats_collector"), 2*time.Second, m, options.WithEventCallback(pprint))
	if err := coll.Init(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	if err := coll.Start(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		server := &http.Server{
			Addr:    ":8080",
			Handler: mux,
		}
		logger.Info("starting metrics server", slog.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("failed to start metrics server", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	<-stopper
	logger.Info("stopping")
	coll.Shutdown()
}
