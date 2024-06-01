package pprofreceiver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/samber/lo"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type pprofReceiver struct {
	cfg  *Config
	done chan struct{}

	logger   *zap.Logger
	consumer consumer.Logs

	endpointClients []*endpointClient
}

var _ component.Component = (*pprofReceiver)(nil)

func NewPprofReceiver(cfg *Config, logger *zap.Logger) *pprofReceiver {
	return &pprofReceiver{
		done:            make(chan struct{}),
		logger:          logger,
		cfg:             cfg,
		endpointClients: make([]*endpointClient, 0),
	}
}

func (p *pprofReceiver) Start(_ context.Context, _ component.Host) error {
	dataQueue := make(chan queueData)
	for _, endp := range p.cfg.Endpoints {
		client, err := newEndpointClient(p.cfg.Global, endp, p.logger)
		if err != nil {
			return err
		}
		p.endpointClients = append(p.endpointClients, client)
	}
	p.logger.Info(
		fmt.Sprintf("starting pprof receiver with global {interval : %d, seconds : %d, labels : %v}", *p.cfg.Global.CollectionInterval, *p.cfg.Global.Seconds, *p.cfg.Global.Labels))
	p.logger.Info(fmt.Sprintf("starting pprof receiver with %d endpoints...", len(p.endpointClients)))

	// start endpoint collectors
	go func() {
		ctx, ca := context.WithCancel(context.Background())
		defer ca()
		for _, client := range p.endpointClients {
			client := client
			p.logger.Info(fmt.Sprintf("starting client for endpoint : %s", client.config.Endpoint))
			go func() {
				client.run(ctx, dataQueue)
				p.logger.Info(fmt.Sprintf("client for endpoint : %s stopped", client.config.Endpoint))
			}()
		}
		<-p.done
	}()

	// start collection
	go func() {
		for {
			select {
			case <-p.done:
				return
			case data := <-dataQueue:
				logs := plog.NewLogs()
				rsc := logs.ResourceLogs().AppendEmpty()
				for k, v := range data.labels {
					rsc.Resource().Attributes().PutStr(k, v)
				}
				scpL := rsc.ScopeLogs().AppendEmpty()
				lr := scpL.LogRecords().AppendEmpty()
				by := lr.Body().SetEmptyBytes()
				by.Append(data.data...)
				p.consumer.ConsumeLogs(context.Background(), logs)
			}
		}
	}()
	return nil
}

func (p *pprofReceiver) Shutdown(_ context.Context) error {
	defer close(p.done)
	select {
	case p.done <- struct{}{}:
	default:
	}
	return nil
}

func (p *pprofReceiver) registerLogsConsumer(consumer consumer.Logs) error {
	p.consumer = consumer
	return nil
}

type queueData struct {
	data   []byte
	labels map[string]string
}

type reqWrapper struct {
	req                *http.Request
	labels             map[string]string
	collectionInterval time.Duration
}

type endpointClient struct {
	logger *zap.Logger
	client http.Client
	config EndpointConfig
	reqs   []*reqWrapper
}

func newEndpointClient(
	global GenericConfig,
	endp EndpointConfig,
	logger *zap.Logger,
) (*endpointClient, error) {
	ec := &endpointClient{
		config: endp,
		client: *http.DefaultClient,
		logger: logger,
	}
	cfg := Merge(&global, endp.GenericConfig)
	reqs := []*reqWrapper{}
	for key, e := range endp.Targets {
		c := Merge(cfg, e)
		req, err := ec.constructRequest(key, c.Seconds, *c.CollectionInterval, *c.Labels)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, req)
	}
	ec.reqs = reqs
	return ec, nil
}

func (e *endpointClient) constructRequest(
	suffix string,
	seconds *int,
	collectionInterval time.Duration,
	labels map[string]string,
) (*reqWrapper, error) {
	target := e.config.Endpoint + "/debug/pprof/" + suffix
	if seconds != nil {
		target += fmt.Sprintf("?seconds=%d", *seconds)
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	return &reqWrapper{
		req:                req,
		collectionInterval: collectionInterval,
		labels:             labels,
	}, nil
}

// blocks until ctx is done
func (e *endpointClient) run(ctx context.Context, consumerQueue chan<- queueData) {
	for _, req := range e.reqs {
		req := req
		go func() {
			e.logger.Info("starting client for endpoint", zap.String("url", req.req.URL.String()))
			if req.collectionInterval == 0 {
				for {
				RETRYA:
					select {
					case <-ctx.Done():
						return
					default:
						e.logger.Debug("making request", zap.String("url", req.req.URL.String()))
						resp, err := e.client.Do(req.req)
						if err != nil {
							e.logger.Error("failed to make request", zap.Error(err))
							goto RETRYA
						}
						data, err := io.ReadAll(resp.Body)
						if err != nil {
							e.logger.Error("failed to read response body", zap.Error(err))
							resp.Body.Close()
							goto RETRYA
						}
						consumerQueue <- queueData{
							data: data,
							labels: lo.Assign(
								map[string]string{
									"pprof_endpoint": req.req.URL.String(),
								},
								req.labels,
							),
						}
					}
				}
			} else {
				e.logger.Info("starting client for endpoint", zap.String("url", req.req.URL.String()))
				t := time.NewTicker(req.collectionInterval)
				defer t.Stop()
				for {
				RETRYB:
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						e.logger.Debug("making request", zap.String("url", req.req.URL.String()))
						resp, err := e.client.Do(req.req)
						if err != nil {
							e.logger.Error("failed to make request", zap.Error(err))
							goto RETRYB
						}
						data, err := io.ReadAll(resp.Body)
						if err != nil {
							e.logger.Error("failed to read response body", zap.Error(err))
							resp.Body.Close()
							goto RETRYB
						}
						consumerQueue <- queueData{
							data: data,
							labels: lo.Assign(
								map[string]string{
									"pprof_endpoint": req.req.URL.String(),
								},
								req.labels,
							),
						}
					}
				}
			}
		}()
	}
	<-ctx.Done()
}
