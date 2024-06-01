package pyro

import (
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/sd"
)

type RelabelConfig struct {
	SourceLabels []string
	Separator    string
	Regex        string
	TargetLabel  string `yaml:"target_label,omitempty"`
	Replacement  string `yaml:"replacement,omitempty"`
	Action       string
}

type Config struct {
	TargetsOptions sd.TargetsOptions
	RelabelConfig  []*RelabelConfig
	SessionOptions ebpfspy.SessionOptions
}
