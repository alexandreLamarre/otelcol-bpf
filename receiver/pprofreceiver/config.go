package pprofreceiver

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"go.opentelemetry.io/collector/component"
)

var (
	ErrInvalidDelta = errors.New("invalid delta value, must be positive")
	allowedTargets  = []string{
		"allocs",
		"block",
		"goroutine",
		"heap",
		"mutex",
		"profile",
		"threadcreate",
		"trace",
	}
)

type Config struct {
	Endpoints []EndpointConfig `mapstructure:"endpoints"`
	Global    GenericConfig    `mapstructure:"global"`
}

func (c *Config) Validate() error {
	if c.Global.CollectionInterval == nil {
		return ErrInvalidDelta
	}
	if *c.Global.CollectionInterval < 0 {
		return ErrInvalidDelta
	}
	if len(c.Endpoints) == 0 {
		return errors.New("no endpoints configured")
	}
	for _, e := range c.Endpoints {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

var _ component.Config = (*Config)(nil)

type GenericConfig struct {
	CollectionInterval *time.Duration     `mapstructure:"collection_interval"`
	Labels             *map[string]string `mapstructure:"labels"`
	Seconds            *int               `mapstructure:"seconds"`
}

func Merge(ours, theirs *GenericConfig) *GenericConfig {
	if ours == nil {
		panic("base generic config is nil")
	}
	var cfg *GenericConfig
	if theirs == nil {
		cfg = &GenericConfig{
			CollectionInterval: ours.CollectionInterval,
			Labels:             ours.Labels,
			Seconds:            ours.Seconds,
		}
	} else {
		cfg = &GenericConfig{
			CollectionInterval: lo.ToPtr(lo.FromPtrOr(theirs.CollectionInterval, *ours.CollectionInterval)),
			Labels:             lo.ToPtr(lo.Assign(*ours.Labels, lo.FromPtrOr(theirs.Labels, map[string]string{}))),
			Seconds:            lo.ToPtr(lo.FromPtrOr(theirs.Seconds, *ours.Seconds)),
		}
	}
	return cfg
}

func (g *GenericConfig) Validate() error {
	return nil
}

type EndpointConfig struct {
	Id            string                    `mapstructure:"id"`
	ExtraLabels   map[string]string         `mapstructure:"extra_labels"`
	Endpoint      string                    `mapstructure:"endpoint"`
	GenericConfig *GenericConfig            `mapstructure:"local"`
	Targets       map[string]*GenericConfig `mapstructure:"targets"`
}

func (e *EndpointConfig) Validate() error {
	if e.Id == "" {
		return errors.New("id must be set")
	}

	for key := range maps.Keys(e.ExtraLabels) {
		if slices.Contains(reservedLabels, key) {
			return fmt.Errorf("label %s is reserved", key)
		}
	}
	if e.Endpoint == "" {
		return errors.New("endpoint must be set")
	}
	for k := range e.Targets {
		if !lo.Contains(allowedTargets, k) {
			return fmt.Errorf(
				"invalid target %s, should be one of {%s}",
				k,
				strings.Join(allowedTargets, ", "),
			)
		}
	}
	return nil

}

type AllocConfig struct {
	*GenericConfig
}
