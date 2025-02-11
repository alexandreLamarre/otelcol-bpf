package tcp

import (
	"log/slog"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/bpfutil"
	"github.com/cilium/ebpf/link"
)

type TcpStatsCollector struct {
	logger          *slog.Logger
	stopC           chan struct{}
	collectInterval time.Duration
	objs            tcpconnlatObjects
	cb              TcpStatsCallback
}

type TcpconnlatTrafficKey tcpconnlatTrafficKey
type TcpconnlatTrafficValue tcpconnlatTrafficValue

type TcpStatsCallback func(key TcpconnlatTrafficKey, val TcpconnlatTrafficValue)

func NewTcpStatsCollector(
	logger *slog.Logger,
	collectInterval time.Duration,
	cb TcpStatsCallback,
) *TcpStatsCollector {
	return &TcpStatsCollector{
		logger:          logger,
		stopC:           make(chan struct{}),
		objs:            tcpconnlatObjects{},
		collectInterval: collectInterval,
		cb:              cb,
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
					c.cb(TcpconnlatTrafficKey(key), TcpconnlatTrafficValue(val))
				}
			case <-c.stopC:
				c.logger.Info("exiting from tcp stats collector")
				return
			}
		}
	}()
	return nil
}

func (c *TcpStatsCollector) Shutdown() error {
	c.logger.Info("shutting down...")
	close(c.stopC)
	return nil
}
