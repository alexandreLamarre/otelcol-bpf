package tcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type TCPMetrics struct {
	ctx               context.Context
	BpfTCPConnlatency metric.Int64Histogram
	BpfTCPRx          metric.Int64Gauge
	BpfTCPTx          metric.Int64Gauge
}

func NewTcpMetrics(ctx context.Context, meter metric.Meter) (*TCPMetrics, error) {
	t := &TCPMetrics{
		ctx: ctx,
	}
	var errs error
	var err error
	t.BpfTCPConnlatency, err = meter.Int64Histogram(
		"bpf.tcp.connlatency",
		metric.WithDescription("Histogram of TCP connection latency"),
		metric.WithUnit("ns"),
		metric.WithExplicitBucketBoundaries(0, 100, 250, 500, 750, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000, 100000000, 200000000, 500000000, 1000000000),
	)
	errs = errors.Join(errs, err)
	t.BpfTCPRx, err = meter.Int64Gauge(
		"bpf.tcp.rx",
		metric.WithDescription("TCP received bytes"),
		metric.WithUnit("bytes"),
	)
	errs = errors.Join(errs, err)
	t.BpfTCPTx, err = meter.Int64Gauge(
		"bpf.tcp.tx",
		metric.WithDescription("TCP transmitted bytes"),
		metric.WithUnit("bytes"),
	)
	errs = errors.Join(errs, err)
	return t, errs
}

func (t *TCPMetrics) ConnLatCallback(event TcpconnLatEvent) {
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
	attrs := metric.WithAttributes(attribute.KeyValue{
		Key:   attribute.Key("saddr"),
		Value: attribute.StringValue(saddr),
	},
		attribute.KeyValue{
			Key:   attribute.Key("daddr"),
			Value: attribute.StringValue(daddr),
		},
		attribute.KeyValue{
			Key:   attribute.Key("comm"),
			Value: attribute.StringValue(name),
		},
		attribute.KeyValue{
			Key:   attribute.Key("tgid"),
			Value: attribute.Int64Value(int64(event.Tgid)),
		},
		attribute.KeyValue{
			Key:   attribute.Key("af"),
			Value: attribute.Int64Value(int64(event.Af)),
		},
	)
	t.BpfTCPConnlatency.Record(t.ctx, int64(event.DeltaUs), attrs)
}

func (t *TCPMetrics) ConnStatsCallback(key TcpconnlatTrafficKey, val TcpconnlatTrafficValue) {
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
	attrs := metric.WithAttributes(attribute.KeyValue{
		Key:   attribute.Key("saddr"),
		Value: attribute.StringValue(saddr),
	},
		attribute.KeyValue{
			Key:   attribute.Key("daddr"),
			Value: attribute.StringValue(daddr),
		},
		attribute.KeyValue{
			Key:   attribute.Key("comm"),
			Value: attribute.StringValue(name),
		},
		attribute.KeyValue{
			Key:   attribute.Key("pid"),
			Value: attribute.Int64Value(int64(key.Pid)),
		},
	)

	if rx := val.Rx; rx > 0 {
		t.BpfTCPRx.Record(t.ctx, int64(val.Rx), attrs)

	}
	if tx := val.Tx; tx > 0 {

		t.BpfTCPTx.Record(t.ctx, int64(val.Tx), attrs)
	}

}
