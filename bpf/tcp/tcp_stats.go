package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/bpfutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/metrics"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/options"
	"github.com/cilium/ebpf/link"
)

type TcpStatsCollector struct {
	logger          *slog.Logger
	stopC           chan struct{}
	collectInterval time.Duration
	objs            tcpconnlatObjects
	metrics         metrics.Metrics

	opts *options.CollectorOptions[TcpconnlatTrafficPair]
}

type TcpconnlatTrafficKey tcpconnlatTrafficKey
type TcpconnlatTrafficValue tcpconnlatTrafficValue

type TcpconnlatTrafficPair struct {
	Key TcpconnlatTrafficKey
	Val TcpconnlatTrafficValue
}

type TcpStatsCallback func(key TcpconnlatTrafficKey, val TcpconnlatTrafficValue)

func NewTcpStatsCollector(
	logger *slog.Logger,
	collectInterval time.Duration,
	metrics metrics.Metrics,
	opts ...options.CollectorOption[TcpconnlatTrafficPair],
) *TcpStatsCollector {
	option := options.NewCollectorOptions(opts...)
	return &TcpStatsCollector{
		logger:          logger,
		stopC:           make(chan struct{}),
		objs:            tcpconnlatObjects{},
		collectInterval: collectInterval,
		metrics:         metrics,
		opts:            option,
	}
}

func (c *TcpStatsCollector) Init() error {
	c.logger.Info("requesting memlock removal")
	if err := bpfutil.RemoveMemlock(); err != nil {
		return err
	}
	c.logger.Info("loading bpf objects")
	if err := loadTcpconnlatObjects(&c.objs, nil); err != nil {
		return err
	}
	return nil
}

func (c *TcpStatsCollector) Start() error {
	c.logger.Info("attaching fentry tcp_sendmsg")
	tcpSendMsg, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.FentryTcpSendmsg,
	})
	if err != nil {
		return err
	}
	c.logger.Info("attaching fentry tcp_cleanup_rbuf")
	tcpCleanupRbuf, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.FentryTcpCleanupRbuf,
	})
	if err != nil {
		tcpSendMsg.Close()
		return err
	}

	go func() {
		defer tcpSendMsg.Close()
		defer tcpCleanupRbuf.Close()
		ticker := time.NewTicker(c.collectInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tcpMap := c.objs.TrafficMap
				c.logger.Debug("reading from tcp traffic stats map")
				iter := tcpMap.Iterate()
				var key tcpconnlatTrafficKey
				var val tcpconnlatTrafficValue
				for iter.Next(&key, &val) {
					if iter.Err() != nil {
						c.logger.With("err", iter.Err()).Error("failed to iterate over traffic map")
						continue
					}
					c.record(TcpconnlatTrafficKey(key), TcpconnlatTrafficValue(val))
					if c.opts.EventCallback != nil {
						c.opts.EventCallback(TcpconnlatTrafficPair{
							Key: TcpconnlatTrafficKey(key),
							Val: TcpconnlatTrafficValue(val),
						})
					}
				}
			case <-c.stopC:
				c.logger.Info("exiting from tcp stats collector")
				return
			}
		}
	}()
	return nil
}

func (c *TcpStatsCollector) record(key TcpconnlatTrafficKey, val TcpconnlatTrafficValue) {
	isIpv4 := byteutil.EmptyIpv6(byteutil.Ipv6Str(key.SaddrV6))
	name := byteutil.CCharSliceToStr(key.Name[:])
	var saddr, daddr string
	if isIpv4 {
		saddr = byteutil.Ipv4Str(key.SaddrV4)
		daddr = byteutil.Ipv4Str(key.DaddrV4)
	} else {
		saddr = byteutil.Ipv6Str(key.SaddrV6)
		daddr = byteutil.Ipv6Str(key.DaddrV6)
	}
	saddr += fmt.Sprintf(":%d", key.Lport)
	daddr += fmt.Sprintf(":%d", key.Dport)

	if rx := val.Rx; rx > 0 {
		c.metrics.MetricBpfTcpRx.Record(context.TODO(), int64(val.Rx), int64(key.Pid), name, saddr, daddr)

	}
	if tx := val.Tx; tx > 0 {
		c.metrics.MetricBpfTcpTx.Record(context.TODO(), int64(val.Tx), int64(key.Pid), name, saddr, daddr)
	}

}

func (c *TcpStatsCollector) Shutdown() error {
	c.logger.Info("shutting down...")
	close(c.stopC)
	return nil
}
