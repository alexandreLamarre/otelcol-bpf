package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/bpfutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/metrics"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/options"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func readTcpconnEvent(buf *bytes.Buffer, event *tcpconnlatEvent) error {
	if err := binary.Read(buf, binary.NativeEndian, &event.SaddrV4); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.SaddrV6); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.DaddrV4); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.DaddrV6); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.Comm); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.DeltaUs); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.TsUs); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.Tgid); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.Af); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.Lport); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.NativeEndian, &event.Dport); err != nil {
		return err
	}
	return nil
}

type TcpconnLatEvent tcpconnlatEvent
type TcpConnLatCallback func(event TcpconnLatEvent)

type TcpConnLatCollector struct {
	logger  *slog.Logger
	stopC   chan struct{}
	objs    tcpconnlatObjects
	metrics metrics.Metrics
	rd      *perf.Reader

	opts *options.CollectorOptions[TcpconnLatEvent]
}

func NewTcpConnLatCollector(
	logger *slog.Logger,
	metrics metrics.Metrics,
	opts ...options.CollectorOption[TcpconnLatEvent],
) *TcpConnLatCollector {
	option := options.NewCollectorOptions(opts...)
	return &TcpConnLatCollector{
		logger:  logger,
		metrics: metrics,
		stopC:   make(chan struct{}),
		objs:    tcpconnlatObjects{},
		opts:    option,
	}
}

func (c *TcpConnLatCollector) Init() error {
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

func (c *TcpConnLatCollector) Start() error {
	c.logger.Info("attach tcpv4 connect")
	connectV4, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.FentryTcpV4Connect,
	})
	if err != nil {
		return err
	}

	c.logger.Info("attach tcpv6 connect")
	connectV6, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.FentryTcpV6Connect,
	})
	if err != nil {
		return err
	}

	c.logger.Info("attach tcprecvstate")
	rcvState, err := link.AttachTracing(link.TracingOptions{
		Program: c.objs.FentryTcpRcvStateProcess,
	})
	if err != nil {
		return err
	}

	c.logger.Info("attach sock destroy")

	destroySock, err := link.Tracepoint("tcp", "tcp_destroy_sock", c.objs.TcpDestroySock, nil)
	if err != nil {
		return err
	}

	c.logger.Info("opening perf buffer reader")
	rd, err := perf.NewReader(c.objs.Events, os.Getpagesize())
	if err != nil {
		return err
	}
	c.rd = rd

	go func() {
		defer connectV4.Close()
		defer connectV6.Close()
		defer rcvState.Close()
		defer destroySock.Close()

		c.logger.Info("Starting perf event reader...")
		for {
			c.logger.Debug("waiting for events")
			record, err := rd.Read()
			c.logger.Debug("got events")
			if errors.Is(err, perf.ErrClosed) {
				c.logger.Info("perf reader closed")
				return
			}
			if err != nil {
				c.logger.With("err", err).Error("failed to read from perf buffer array")
				continue
			}
			if record.LostSamples != 0 {
				c.logger.With("samples", record.LostSamples).Warn("perf event buffer full, dropped samples")
				continue
			}
			tcpE := &tcpconnlatEvent{}
			if err := readTcpconnEvent(bytes.NewBuffer(record.RawSample), tcpE); err != nil {
				c.logger.With("err", err).Error("failed to read tcpconn event")
				continue
			}
			c.record(TcpconnLatEvent(*tcpE))
			if c.opts.EventCallback != nil {
				c.opts.EventCallback(TcpconnLatEvent(*tcpE))
			}
		}
	}()
	return nil
}

func (c *TcpConnLatCollector) record(event TcpconnLatEvent) {
	name := byteutil.CCharSliceToStr(event.Comm[:])
	isIpv4 := byteutil.EmptyIpv6(byteutil.Ipv6Str(event.SaddrV6))
	var saddr, daddr string
	if isIpv4 {
		saddr = byteutil.Ipv4Str(event.SaddrV4)
		daddr = byteutil.Ipv4Str(event.DaddrV4)
	} else {
		saddr = byteutil.Ipv6Str(event.SaddrV6)
		daddr = byteutil.Ipv6Str(event.DaddrV6)
	}
	saddr += fmt.Sprintf(":%d", event.Lport)
	daddr += fmt.Sprintf(":%d", event.Dport)
	c.metrics.MetricBpfTcpConnlatency.Record(context.TODO(), float64(event.DeltaUs)*1000, int64(event.Tgid), name, saddr, daddr, int(event.Af))
}

func (c *TcpConnLatCollector) Shutdown() error {
	c.logger.Info("shutting down...")
	// FIXME: hack
	if c.rd == nil {
		return nil
	}
	if err := c.rd.Close(); err != nil {
		c.logger.With("err", err).Error("closing perf event reader: %s")
	}
	return nil
}
