package bpftcp

import (
	"context"

	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetrics, metadata.MetricsStability),
	)
}
func createDefaultConfig() component.Config {
	return &Config{}
}

func createMetrics(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	return NewMetricsReceiver(set.TelemetrySettings)
	// oCfg := cfg.(*Config)

	// addScraperOptions, err := initScrapers(oCfg)
	// if err != nil {
	// 	return nil, err
	// }

	// return scraperhelper.NewMetricsController(
	// 	&oCfg.ControllerConfig,
	// 	set,
	// 	consumer,
	// 	addScraperOptions...,
	// )
}

// func initScrapers(cfg *Config) ([]scraperhelper.ControllerOption, error) {
// 	scraperControllerOptions := []scraperhelper.ControllerOption{}

// 	for key, cfg := range cfg.Scrapers {
// 		factory, err := getFactory(key, scraperFactories)
// 		if err != nil {
// 			return nil, err
// 		}
// 		scraperControllerOptions = append(scraperControllerOptions, scraperhelper.AddFactoryWithConfig(factory, cfg))
// 	}
// 	return scraperControllerOptions, nil
// }

// func getFactory(key component.Type, factories map[component.Type]scraper.Factory) (s scraper.Factory, err error) {
// 	factory, ok := factories[key]
// 	if !ok {
// 		return nil, fmt.Errorf("bpftcp scraper factory not found for key: %q", key)
// 	}

// 	return factory, nil
// }
