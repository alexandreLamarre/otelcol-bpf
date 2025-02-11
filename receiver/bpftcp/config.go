package bpftcp

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

type Config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`
	Scrapers                       map[component.Type]component.Config `mapstructure:"-"`
}

// Validate checks the receiver configuration is valid
func (cfg *Config) Validate() error {
	if len(cfg.Scrapers) == 0 {
		return errors.New("must specify at least one scraper when using hostmetrics receiver")
	}
	return nil
}

// Unmarshal a config.Parser into the config struct.
func (cfg *Config) Unmarshal(componentParser *confmap.Conf) error {
	if componentParser == nil {
		return nil
	}

	// load the non-dynamic config normally
	if err := componentParser.Unmarshal(cfg, confmap.WithIgnoreUnused()); err != nil {
		return err
	}

	// dynamically load the individual collector configs based on the key name

	cfg.Scrapers = map[component.Type]component.Config{}

	scrapersSection, err := componentParser.Sub("scrapers")
	if err != nil {
		return err
	}

	for keyStr := range scrapersSection.ToStringMap() {
		key, err := component.NewType(keyStr)
		if err != nil {
			return fmt.Errorf("invalid scraper key name: %s", key)
		}
		factory, ok := scraperFactories[key]
		if !ok {
			return fmt.Errorf("invalid scraper key: %s", key)
		}

		scraperSection, err := scrapersSection.Sub(keyStr)
		if err != nil {
			return err
		}
		scraperCfg := factory.CreateDefaultConfig()
		if err = scraperSection.Unmarshal(scraperCfg); err != nil {
			return fmt.Errorf("error reading settings for scraper type %q: %w", key, err)
		}
		cfg.Scrapers[key] = scraperCfg
	}

	return nil
}

var _ component.Config = (*Config)(nil)
