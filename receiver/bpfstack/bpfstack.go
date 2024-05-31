package bpfstack

import (
	"context"
	"fmt"
	"time"

	"github.com/alexandreLamarre/otelbpf/receiver/bpfstack/pyro"
	kitlogzap "github.com/go-kit/kit/log/zap"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap/zapcore"
)

type bpfStackReceiver struct {
	cfg            *Config
	stackCollector *pyro.StackCollector

	nextTraces  consumer.Traces
	nextMetrics consumer.Metrics
	nextLogs    consumer.Logs

	done chan struct{}

	settings *receiver.CreateSettings
}

func newBpfStackReceiver(cfg *Config, set *receiver.CreateSettings) (*bpfStackReceiver, error) {
	logger := kitlogzap.NewZapSugarLogger(set.Logger, zapcore.DebugLevel)

	stackCollector, err := pyro.NewStackCollector(
		logger,
		nil,
		time.Second*5,
		time.Second*15,
	)
	if err != nil {
		return nil, err
	}

	return &bpfStackReceiver{
		cfg:            cfg,
		settings:       set,
		stackCollector: stackCollector,
		done:           make(chan struct{}),
	}, nil
}

func (b *bpfStackReceiver) Start(ctx context.Context, host component.Host) error {
	profiles, err := b.stackCollector.Start()
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case p := <-profiles:
				b.settings.Logger.Info("Received profile from ebpf")
				b.settings.Logger.Debug(fmt.Sprintf("Received profile: %v", p))
				if b.nextLogs != nil {
					b.settings.Logger.Info("Should send profile to logs")
					// TODO : how do I actuall create this data hahaha
					logs := plog.NewLogs()
					b.nextLogs.ConsumeLogs(ctx, logs)

				}
				if b.nextMetrics != nil {
					b.settings.Logger.Info("Should send profile to metrics")
					// TODO : how do I actuall create this data hahaha
					metrics := pmetric.NewMetrics()
					b.nextMetrics.ConsumeMetrics(ctx, metrics)
				}
				if b.nextTraces != nil {
					b.settings.Logger.Info("Should send profile to traces")
					// TODO : how do I actuall create this data hahaha
					traces := ptrace.NewTraces()
					b.nextTraces.ConsumeTraces(ctx, traces)
				}
			case <-ctx.Done():
				return
			case <-b.done:
				return
			}
		}
	}()
	return nil
}

func (b *bpfStackReceiver) Shutdown(ctx context.Context) error {
	defer close(b.done)
	select {
	case b.done <- struct{}{}:
	default:
	}
	if err := b.stackCollector.Shutdown(); err != nil {
		return err
	}
	return nil
}

var _ component.Component = (*bpfStackReceiver)(nil)

func (r *bpfStackReceiver) registerTraceConsumer(tc consumer.Traces) {
	r.nextTraces = tc
}

func (r *bpfStackReceiver) registerMetricsConsumer(mc consumer.Metrics) {
	r.nextMetrics = mc
}

func (r *bpfStackReceiver) registerLogsConsumer(lc consumer.Logs) {
	r.nextLogs = lc
}
