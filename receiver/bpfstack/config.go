package bpfstack

import "go.opentelemetry.io/collector/component"

type Config struct {
}

var _ component.Config = (*Config)(nil)
