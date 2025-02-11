package tcpscraper

import "github.com/alexandreLamarre/otelcol-bpf/receiver/bpftcp/internal/scraper/tcpscraper/internal/metadata"

type Config struct {
	metadata.MetricsBuilderConfig `mapstructure:",squash"`
}
