package tcptracer

import (
	"context"

	"go.opentelemetry.io/collector/component"
)

type tcpTracerReceiver struct {
	cfg *Config
}

var _ component.Component = (*tcpTracerReceiver)(nil)

func (t *tcpTracerReceiver) Start(_ context.Context, _ component.Host) error {
	panic("implement me")
}

func (t *tcpTracerReceiver) Shutdown(_ context.Context) error {
	panic("implement me")
}
