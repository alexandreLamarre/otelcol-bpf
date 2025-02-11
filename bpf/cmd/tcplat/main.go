package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
)

func pprint(event tcp.TcpconnLatEvent) {
	slog.Default().Info(
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
}

func main() {
	logger := slog.Default()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	coll := tcp.NewTcpConnLatCollector(logger.With("name", "tcp_lat_collector"), pprint)
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
