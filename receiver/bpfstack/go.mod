module github.com/alexandreLamarre/otelbpf/receiver/bpfstack

go 1.22.3

require (
	github.com/alexandreLamarre/otelbpf v0.101.0
	github.com/cilium/ebpf v0.11.0
	github.com/go-kit/kit v0.12.0
	github.com/go-kit/log v0.2.1
	github.com/google/pprof v0.0.0-20240227163752-401108e1b7e7
	github.com/google/uuid v1.6.0
	github.com/grafana/pyroscope/api v0.4.0
	github.com/grafana/pyroscope/ebpf v0.4.7
	github.com/klauspost/compress v1.17.7
	github.com/prometheus/client_golang v1.19.1
	github.com/prometheus/common v0.53.0
	github.com/prometheus/prometheus v0.51.2
	github.com/samber/lo v1.39.0
	github.com/stretchr/testify v1.9.0
	go.opentelemetry.io/collector/component v0.101.0
	go.opentelemetry.io/collector/confmap v0.101.0
	go.opentelemetry.io/collector/consumer v0.101.0
	go.opentelemetry.io/collector/pdata v1.8.0
	go.opentelemetry.io/collector/receiver v0.101.0
	go.opentelemetry.io/collector/semconv v0.96.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
)

replace github.com/alexandreLamarre/otelbpf => ../..

require (
	github.com/avvmoto/buf-readerat v0.0.0-20171115124131-a17c8cb89270 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.0.0-alpha.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/grafana/regexp v0.0.0-20221123153739-15dc172cd2db // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20230524184225-eabc099b10ab // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.101.0 // indirect
	go.opentelemetry.io/otel v1.26.0 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.48.0 // indirect
	go.opentelemetry.io/otel/metric v1.26.0 // indirect
	go.opentelemetry.io/otel/sdk v1.26.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.26.0 // indirect
	go.opentelemetry.io/otel/trace v1.26.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240401170217-c3f982113cda // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
