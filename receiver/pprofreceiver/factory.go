package pprofreceiver

import (
	"context"
	"time"

	"github.com/alexandreLamarre/otelbpf/receiver/pprofreceiver/internal/metadata"
	"github.com/samber/lo"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithLogs(createLogs, metadata.LogsStability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Endpoints: []EndpointConfig{},
		Global: GenericConfig{
			CollectionInterval: lo.ToPtr(time.Second * 0),
			Labels:             lo.ToPtr(map[string]string{}),
			Seconds:            lo.ToPtr(5),
		},
	}
}

func createLogs(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	oCfg := cfg.(*Config)
	r := NewPprofReceiver(oCfg, set.Logger)
	r.registerLogsConsumer(consumer)
	return r, nil
}
