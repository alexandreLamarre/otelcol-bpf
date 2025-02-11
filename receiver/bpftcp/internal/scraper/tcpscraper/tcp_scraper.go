package tcpscraper

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/tcp"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/scraper/tcpscraper/internal/metadata"
	"github.com/shirou/gopsutil/host"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/scraper"
)

type tcpScraper struct {
	settings  scraper.Settings
	config    *Config
	mb        *metadata.MetricsBuilder
	statsColl *tcp.TcpStatsCollector
	recordMu  sync.Mutex
}

func newTcpScraper(_ context.Context, settings scraper.Settings, config *Config) (*tcpScraper, error) {
	s := &tcpScraper{
		settings: settings,
		config:   config,
		mb:       nil,
	}
	s.statsColl = tcp.NewTcpStatsCollector(
		slog.Default().With("collector", "tcpstats"),
		15*time.Second,
		func(key tcp.TcpconnlatTrafficKey, val tcp.TcpconnlatTrafficValue) {
			now := pcommon.NewTimestampFromTime(time.Now())
			// slog.Default().Info(fmt.Sprintf("tcp stats : %s", now.String()))
			isEmptyTcp6 := byteutil.EmptyIpv6(byteutil.Ipv6Str(key.SaddrV6))
			if val.Rx > 0 {
				var saddr string
				var daddr string
				if isEmptyTcp6 {
					saddr = byteutil.Ipv4Str(key.SaddrV4)
					daddr = byteutil.Ipv4Str(key.DaddrV4)
				} else {
					saddr = byteutil.Ipv6Str(key.SaddrV6)
					daddr = byteutil.Ipv6Str(key.DaddrV6)
				}
				saddr += fmt.Sprintf(":%d", key.Lport)
				daddr += fmt.Sprintf(":%d", key.Dport)
				name := byteutil.CCharSliceToStr(key.Name[:])
				s.recordMu.Lock()
				s.mb.RecordBpfTCPRxDataPoint(now, int64(val.Rx), int64(key.Pid), name, saddr, daddr)
				s.recordMu.Unlock()
			}
			if val.Tx > 0 {
				var saddr string
				var daddr string
				if isEmptyTcp6 {
					saddr = byteutil.Ipv4Str(key.SaddrV4)
					daddr = byteutil.Ipv4Str(key.DaddrV4)
				} else {
					saddr = byteutil.Ipv6Str(key.SaddrV6)
					daddr = byteutil.Ipv6Str(key.DaddrV6)
				}
				saddr += fmt.Sprintf(":%d", key.Lport)
				daddr += fmt.Sprintf(":%d", key.Dport)
				name := byteutil.CCharSliceToStr(key.Name[:])
				s.recordMu.Lock()
				s.mb.RecordBpfTCPTxDataPoint(now, int64(val.Tx), int64(key.Pid), name, saddr, daddr)
				s.recordMu.Unlock()
			}
		})

	if err := s.statsColl.Init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *tcpScraper) start(ctx context.Context, _ component.Host) error {
	bootTime, err := host.BootTimeWithContext(ctx)
	if err != nil {
		return err
	}
	s.mb = metadata.NewMetricsBuilder(s.config.MetricsBuilderConfig, s.settings, metadata.WithStartTime(pcommon.Timestamp(bootTime*1e9)))

	if err := s.statsColl.Start(); err != nil {
		return err
	}
	return nil
}

func (s *tcpScraper) scrape(context.Context) (pmetric.Metrics, error) {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	return s.mb.Emit(), nil
}

func (s *tcpScraper) shutdown(context.Context) error {
	s.statsColl.Shutdown()
	return nil
}
