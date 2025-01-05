package bpfstack

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpfstack/internal/metadata"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpfstack/pprof"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/bpfstack/pyro"
	"github.com/alexandreLamarre/otelcol-bpf/receiver/pprofreceiver"
	kitlogzap "github.com/go-kit/kit/log/zap"
	"github.com/google/pprof/profile"
	"github.com/google/uuid"
	pushv1 "github.com/grafana/pyroscope/api/gen/proto/go/push/v1"
	"github.com/klauspost/compress/gzip"
	"github.com/samber/lo"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver"
	conventions "go.opentelemetry.io/collector/semconv/v1.9.0"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type bpfStackReceiver struct {
	cfg            *Config
	stackCollector *pyro.StackCollector

	nextTraces  consumer.Traces
	nextMetrics consumer.Metrics
	nextLogs    consumer.Logs

	done chan struct{}

	settings *receiver.Settings
}

func newBpfStackReceiver(cfg *Config, set *receiver.Settings) (*bpfStackReceiver, error) {
	logger := kitlogzap.NewZapSugarLogger(set.Logger, zapcore.DebugLevel)

	stackCollector, err := pyro.NewStackCollector(
		logger,
		nil,
		cfg.TargetDiscoveryFreq,
		cfg.CollectFreq,
	)
	if err != nil {
		return nil, err
	}

	return &bpfStackReceiver{
		cfg:            cfg,
		settings:       set,
		stackCollector: stackCollector,
		done:           make(chan struct{}),
	}, nil
}

func reduceRaw(req *pushv1.PushRequest, logger *zap.Logger) ([]*ProfileSeries, error) {
	arr := []*ProfileSeries{}
	for _, ser := range req.Series {
		newSeries := &ProfileSeries{
			logger: logger,
			Labels: map[string]string{},
			Series: []*profile.Profile{},
		}
		for _, label := range ser.Labels {
			newSeries.Labels[label.Name] = label.Value
		}
		for _, s := range ser.Samples {
			bufR := bytes.NewReader(s.RawProfile)
			r, err := gzip.NewReader(bufR)
			if err != nil {
				return nil, err
			}
			profile, err := profile.Parse(r)
			if err != nil {
				return nil, err
			}
			newSeries.Series = append(newSeries.Series, profile)
		}
		arr = append(arr, newSeries)
	}
	return arr, nil
}

func (b *bpfStackReceiver) Start(ctx context.Context, host component.Host) error {
	profiles, err := b.stackCollector.Start()
	if err != nil {
		return err
	}
	go b.run(ctx, profiles)
	return nil
}

func (b *bpfStackReceiver) Shutdown(ctx context.Context) error {
	defer close(b.done)
	select {
	case b.done <- struct{}{}:
	default:
	}
	if err := b.stackCollector.Shutdown(); err != nil {
		return err
	}
	return nil
}

var _ component.Component = (*bpfStackReceiver)(nil)

func (r *bpfStackReceiver) registerTraceConsumer(tc consumer.Traces) {
	r.nextTraces = tc
}

func (r *bpfStackReceiver) registerMetricsConsumer(mc consumer.Metrics) {
	r.nextMetrics = mc
}

func (r *bpfStackReceiver) registerLogsConsumer(lc consumer.Logs) {
	r.nextLogs = lc
}

func (b *bpfStackReceiver) run(ctx context.Context, profiles chan *pushv1.PushRequest) {
	for {
		select {
		case p := <-profiles:
			end := time.Now()
			start := end.Add(-b.cfg.CollectFreq)

			pprofProfiles, err := reduceRaw(p, b.settings.Logger)
			if err != nil {
				panic(err) // FIXME:
			}
			b.settings.Logger.Info(fmt.Sprintf("Received %d stack pprof profiles from ebpf", len(pprofProfiles)))
			b.settings.Logger.Debug(fmt.Sprintf("Received profile: %v", p))
			if b.nextLogs != nil {
				b.settings.Logger.Debug("Sending profiles to logging consumer...")
				for _, prof := range pprofProfiles {
					logs := prof.ToLogs()
					b.nextLogs.ConsumeLogs(ctx, logs)
				}
			}
			if b.nextMetrics != nil {
				b.settings.Logger.Debug("Sending profiles to metrics consumer...")
				for _, prof := range pprofProfiles {
					metrics := prof.ToMetrics()
					b.nextMetrics.ConsumeMetrics(ctx, metrics)
				}
			}
			if b.nextTraces != nil {
				b.settings.Logger.Debug("Sending profiles to traces consumer...")
				for _, prof := range pprofProfiles {
					traces := prof.ToTraces(start, end)
					for _, t := range traces {
						b.nextTraces.ConsumeTraces(ctx, t)
					}
				}
			}
		case <-ctx.Done():
			return
		case <-b.done:
			return
		}
	}
}

type ProfileSeries struct {
	logger *zap.Logger
	Labels map[string]string
	Series []*profile.Profile
}

func (ps *ProfileSeries) ToLogs() plog.Logs {
	logs := plog.NewLogs()
	rsc := logs.ResourceLogs().AppendEmpty()

	var instanceId string
	commName, ok := ps.Labels["comm"]
	if ok {
		instanceId = commName
	}

	serviceName, ok := ps.Labels["service_name"]
	if ok {
		instanceId = serviceName
	}

	if instanceId == "" {
		instanceId = "unknown"
	}

	md := pprofreceiver.Metadata{
		Id:          instanceId,
		ProfileType: "profile",
	}
	labels := lo.Assign(ps.Labels, md.ToLabels())
	for k, v := range labels {
		rsc.Resource().Attributes().PutStr(k, v)
	}

	scpL := rsc.ScopeLogs().AppendEmpty()
	for _, prof := range ps.Series {
		lr := scpL.LogRecords().AppendEmpty()
		b := bytes.NewBuffer([]byte{})
		if err := prof.Write(b); err != nil {
			ps.logger.Warn(fmt.Sprintf("Error writing profile to buffer: %v", err))
			continue
		}
		lr.Body().SetEmptyBytes().Append(b.Bytes()...)
	}
	return logs
}

func (ps *ProfileSeries) ToMetrics() pmetric.Metrics {
	metrics := pmetric.NewMetrics()

	return metrics
}

func (ps *ProfileSeries) ToTraces(start, end time.Time) []ptrace.Traces {
	ret := []ptrace.Traces{}
	for _, prof := range ps.Series {
		traces := ptrace.NewTraces()
		ss := &pprof.StackSet{}
		sampleValue, _, valueType, err := pprof.SampleFormat(prof, "cpu", true) // TODO : could configure via otel receiver config
		ps.logger.Info(fmt.Sprintf("Sample value type: %v", valueType))
		if err != nil {
			ps.logger.Warn(fmt.Sprintf("Error getting sample format: %v", err))
			continue
		}
		ss.MakeInitialStacks(prof, sampleValue)
		ss.FillPlaces()
		constructTraceFromStackSet(traces, ss, ps.Labels, start, end)
		ret = append(ret, traces)
	}
	return ret
}

func constructTraceFromStackSet(
	traces ptrace.Traces,
	ss *pprof.StackSet,
	resourceLabels map[string]string,
	start, end time.Time,
) {
	startTs := pcommon.Timestamp(start.UnixNano())
	endTs := pcommon.Timestamp(end.UnixNano())
	rscSpans := traces.ResourceSpans().AppendEmpty()
	rsc := rscSpans.Resource()
	for k, v := range resourceLabels {
		rsc.Attributes().PutStr(k, v)
	}
	svcName := lo.ValueOr(resourceLabels, "comm", "unknown")
	rsc.Attributes().PutStr(conventions.AttributeServiceName, fmt.Sprintf("%s.cpu.%s", metadata.Type.String(), svcName))
	scopeSpan := rscSpans.ScopeSpans().AppendEmpty()

	// FIXME: probably a better a way to assign IDs
	traceId := pcommon.TraceID(uuid.New())
	prevId := pcommon.SpanID(traceId[0:8])

	for _, stack := range ss.Sources {
		span := scopeSpan.Spans().AppendEmpty()
		// FIXME: probably a better way to assign IDs
		span.SetTraceID(traceId)
		spanIdT := pcommon.TraceID(uuid.New())
		spanId := pcommon.SpanID(spanIdT[0:8])

		span.SetSpanID(spanId)
		// TODO : incorrectly setting parent spans here, in reality we have to look up references to other spans
		span.SetParentSpanID(pcommon.SpanID(prevId))
		prevId = spanId
		span.SetName(stack.FullName)
		span.SetKind(ptrace.SpanKindInternal)
		span.Status().SetCode(ptrace.StatusCodeOk)

		// TODO : we should assign times based on the values of samples compared to total
		span.SetStartTimestamp(startTs)
		span.SetEndTimestamp(endTs)
		for _, disp := range stack.Display {
			event := span.Events().AppendEmpty()
			event.SetName(disp)
			event.SetTimestamp(startTs)
		}
	}
}

//no:lint unused
func stringToTraceId(input string) pcommon.TraceID {
	var tmp [16]byte
	copy(tmp[:], input)
	return pcommon.TraceID(tmp)
}
