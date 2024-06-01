package pprofreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
)

type pprofReceiver struct {
	cfg *Config

	consumer consumer.Logs
}

var _ component.Component = (*pprofReceiver)(nil)

func NewPprofReceiver(cfg *Config) *pprofReceiver {
	return &pprofReceiver{
		cfg: cfg,
	}
}

func (p *pprofReceiver) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *pprofReceiver) Shutdown(_ context.Context) error {
	return nil
}

func (p *pprofReceiver) registerLogsConsumer(consumer consumer.Logs) error {
	p.consumer = consumer
	return nil
}
