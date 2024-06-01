package bpfstack

import (
	"time"

	"go.opentelemetry.io/collector/component"
)

// TODO : embed pyro.Config in here, need custom unmarshaller
type Config struct {
	// Discovery frequency for target discovery, i.e. how often to update information for
	// correlating BPF data with user-friendly information.
	TargetDiscoveryFreq time.Duration `mapstructure:"discovery_frequency"`
	// Collection frequency for BPF data, i.e. how often to collect BPF stack profiles
	CollectFreq time.Duration `mapstructure:"collection_frequency"`
}

var _ component.Config = (*Config)(nil)
