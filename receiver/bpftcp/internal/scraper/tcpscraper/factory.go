package tcpscraper

import (
	"context"

	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/scraper/tcpscraper/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/scraper"
)

func NewFactory() scraper.Factory {
	return scraper.NewFactory(
		metadata.Type,
		createDefaultConfig,
		scraper.WithMetrics(createMetrics, metadata.MetricsStability),
	)
}

// createDefaultConfig creates the default configuration for the Scraper.
func createDefaultConfig() component.Config {
	return &Config{
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
}

func createMetrics(
	ctx context.Context,
	settings scraper.Settings,
	config component.Config,
) (scraper.Metrics, error) {
	cfg := config.(*Config)
	s, err := newTcpScraper(
		ctx,
		settings,
		cfg,
	)
	if err != nil {
		return nil, err
	}

	return scraper.NewMetrics(
		s.scrape,
		scraper.WithStart(s.start),
		scraper.WithShutdown(s.shutdown),
	)
}
