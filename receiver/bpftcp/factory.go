package bpftcp

import (
	"context"
	"fmt"

	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/metadata"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/scraper/tcpscraper"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

var (
	scraperFactories = mustMakeFactories(
		tcpscraper.NewFactory(),
	)
)

func mustMakeFactories(factories ...scraper.Factory) map[component.Type]scraper.Factory {
	factoriesMap, err := scraper.MakeFactoryMap(factories...)
	if err != nil {
		panic(err)
	}
	return factoriesMap
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetrics, metadata.MetricsStability),
	)
}
func createDefaultConfig() component.Config {
	return &Config{
		ControllerConfig: scraperhelper.NewDefaultControllerConfig(),
	}
}

func createMetrics(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	oCfg := cfg.(*Config)

	addScraperOptions, err := initScrapers(oCfg)
	if err != nil {
		return nil, err
	}

	return scraperhelper.NewMetricsController(
		&oCfg.ControllerConfig,
		set,
		consumer,
		addScraperOptions...,
	)
}

func initScrapers(cfg *Config) ([]scraperhelper.ControllerOption, error) {
	scraperControllerOptions := []scraperhelper.ControllerOption{}

	for key, cfg := range cfg.Scrapers {
		factory, err := getFactory(key, scraperFactories)
		if err != nil {
			return nil, err
		}
		scraperControllerOptions = append(scraperControllerOptions, scraperhelper.AddFactoryWithConfig(factory, cfg))
	}
	return scraperControllerOptions, nil
}

func getFactory(key component.Type, factories map[component.Type]scraper.Factory) (s scraper.Factory, err error) {
	factory, ok := factories[key]
	if !ok {
		return nil, fmt.Errorf("bpftcp scraper factory not found for key: %q", key)
	}

	return factory, nil
}

// func createAddScraperOptions(
// 	_ context.Context,
// 	cfg *Config,
// 	factories map[component.Type]scraper.Factory,
// ) ([]scraperhelper.ControllerOption, error) {
// 	scraperControllerOptions := make([]scraperhelper.ControllerOption, 0, len(cfg.Scrapers))

// 	for key, cfg := range cfg.Scrapers {
// 		factory, err := getFactory(key, factories)
// 		if err != nil {
// 			return nil, err
// 		}
// 		factory = internal.NewEnvVarFactory(factory, envMap)
// 		scraperControllerOptions = append(scraperControllerOptions, scraperhelper.AddFactoryWithConfig(factory, cfg))
// 	}

// 	return scraperControllerOptions, nil
// }
