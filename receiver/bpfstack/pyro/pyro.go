//go:build linux

package pyro

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	pushv1 "github.com/grafana/pyroscope/api/gen/proto/go/push/v1"
	typesv1 "github.com/grafana/pyroscope/api/gen/proto/go/types/v1"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
)

type StackCollector struct {
	discoveryFreq time.Duration
	collectFreq   time.Duration
	ebpfspy.Session

	cfg    *Config
	logger log.Logger

	done chan struct{}
}

func NewStackCollector(
	logger log.Logger,
	config *Config,
	discoveryFreq time.Duration,
	collectFreq time.Duration,
) (*StackCollector, error) {
	if config == nil {
		config = defaultConfig()
	}
	targetFinder, err := sd.NewTargetFinder(os.DirFS("/"), logger, convertTargetOptions(logger, config))
	if err != nil {
		panic(fmt.Errorf("ebpf target finder create: %w", err))
	}
	s, err := ebpfspy.NewSession(
		logger,
		targetFinder,
		config.SessionOptions,
	)
	if err != nil {
		return nil, err
	}
	return &StackCollector{
		discoveryFreq: discoveryFreq,
		collectFreq:   collectFreq,
		Session:       s,
		cfg:           config,
		logger:        logger,
		done:          make(chan struct{}),
	}, nil
}

func (s *StackCollector) Start() (chan *pushv1.PushRequest, error) {
	startErr := s.Session.Start()
	if startErr != nil {
		return nil, startErr
	}

	profiles := make(chan *pushv1.PushRequest)
	go func() {
		defer close(profiles)
		discoveryTicker := time.NewTicker(s.discoveryFreq)
		collectTicker := time.NewTicker(s.collectFreq)

		for {
			select {
			case <-discoveryTicker.C:
				s.Session.UpdateTargets(convertTargetOptions(s.logger, s.cfg))
			case <-collectTicker.C:
				s.collectProfiles(profiles)
			case <-s.done:
				return
			}
		}
	}()

	return profiles, nil
}

func (s *StackCollector) collectProfiles(profiles chan *pushv1.PushRequest) {
	builders := pprof.NewProfileBuilders(pprof.BuildersOptions{
		SampleRate:    int64(s.cfg.SessionOptions.SampleRate),
		PerPIDProfile: true,
	})
	err := pprof.Collect(builders, s.Session)

	if err != nil {
		panic(err)
	}
	level.Debug(s.logger).Log("msg", "ebpf collectProfiles done", "profiles", len(builders.Builders))

	for _, builder := range builders.Builders {
		protoLabels := make([]*typesv1.LabelPair, 0, builder.Labels.Len())
		for _, label := range builder.Labels {
			protoLabels = append(protoLabels, &typesv1.LabelPair{
				Name: label.Name, Value: label.Value,
			})
		}

		buf := bytes.NewBuffer(nil)
		_, err := builder.Write(buf)
		if err != nil {
			panic(err)
		}
		req := &pushv1.PushRequest{Series: []*pushv1.RawProfileSeries{{
			Labels: protoLabels,
			Samples: []*pushv1.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}}}
		select {
		case profiles <- req:
		default:
			_ = level.Error(s.logger).Log("err", "dropping profile", "target", builder.Labels.String())
		}

	}
}

func (s *StackCollector) Shutdown() error {
	defer close(s.done)
	select {
	case s.done <- struct{}{}:
	default:
	}
	s.Session.Stop()
	return nil
}
