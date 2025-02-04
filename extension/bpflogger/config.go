package bpflogger

import "go.opentelemetry.io/collector/component"

var _ component.ConfigValidator = (*Config)(nil)

type Config struct {
	TracePipe string `mapstructure:"bpf_trace_pipe"`
}

func (c *Config) Validate() error {
	return nil
}
