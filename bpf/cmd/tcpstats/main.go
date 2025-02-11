package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
)

func pprint(key tcp.TcpconnlatTrafficKey, val tcp.TcpconnlatTrafficValue) {
	ipv4 := byteutil.EmptyIpv6(byteutil.Ipv6Str(key.SaddrV6))
	if ipv4 {
		slog.Default().With("pid", key.Pid, "comm", byteutil.CCharSliceToStr(key.Name[:])).Info(
			fmt.Sprintf(
				"%s -> %s: tx : %d, rx : %d",
				byteutil.Ipv4Str(key.SaddrV4),
				byteutil.Ipv4Str(key.DaddrV4),
				val.Tx, val.Rx,
			),
		)
	} else {
		slog.Default().With("pid", key.Pid, "comm", byteutil.CCharSliceToStr(key.Name[:])).Info(
			fmt.Sprintf(
				"%s -> %s: tx : %d, rx : %d",
				byteutil.Ipv6Str(key.SaddrV6),
				byteutil.Ipv6Str(key.DaddrV6),
				val.Tx, val.Rx,
			),
		)
	}
}

func main() {
	logger := slog.Default()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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
