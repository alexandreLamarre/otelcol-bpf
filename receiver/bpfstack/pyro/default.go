package pyro

import (
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/cpp/demangle"
	ebpfmetrics "github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"github.com/prometheus/client_golang/prometheus"
)

func defaultConfig() *Config {
	return &Config{
		TargetsOptions: sd.TargetsOptions{
			Targets:            nil,
			TargetsOnly:        true,
			DefaultTarget:      nil,
			ContainerCacheSize: 1024,
		},
		RelabelConfig: nil,
		SessionOptions: ebpfspy.SessionOptions{
			CollectUser:               true,
			CollectKernel:             true,
			UnknownSymbolModuleOffset: true,
			UnknownSymbolAddress:      true,
			PythonEnabled:             true,
			CacheOptions: symtab.CacheOptions{

				PidCacheOptions: symtab.GCacheOptions{
					Size:       239,
					KeepRounds: 8,
				},
				BuildIDCacheOptions: symtab.GCacheOptions{
					Size:       239,
					KeepRounds: 8,
				},
				SameFileCacheOptions: symtab.GCacheOptions{
					Size:       239,
					KeepRounds: 8,
				},
			},
			SymbolOptions: symtab.SymbolOptions{
				GoTableFallback:    true,
				PythonFullFilePath: false,
				DemangleOptions:    demangle.DemangleFull,
			},
			Metrics:                  ebpfmetrics.New(prometheus.NewRegistry()),
			SampleRate:               97,
			VerifierLogSize:          (1024*1024*1024 - 1),
			PythonBPFErrorLogEnabled: true,
			PythonBPFDebugLogEnabled: true,
			BPFMapsOptions: ebpfspy.BPFMapsOptions{
				PIDMapSize:     2048,
				SymbolsMapSize: 16384,
			},
		},
	}
}
