package bpflogger

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"
)

const (
	defaultTracePipePath = "/sys/kernel/debug/tracing/trace_pipe"
)

type bpfLoggerExtension struct {
	config    *Config
	bpfLogger *bpfLogger
	logger    *zap.Logger
}

var _ extension.Extension = (*bpfLoggerExtension)(nil)

func newExtension(config *Config, logger *zap.Logger) (*bpfLoggerExtension, error) {
	return &bpfLoggerExtension{
		config:    config,
		bpfLogger: nil,
		logger:    logger,
	}, nil
}

func (b *bpfLoggerExtension) Start(ctx context.Context, _ component.Host) error {
	var tracePipe string
	if b.config.TracePipe == "" {
		tracePipe = defaultTracePipePath
	} else {
		tracePipe = b.config.TracePipe
	}

	l, err := newBpfLogger(tracePipe, b.logger)
	if err != nil {
		return err
	}
	b.bpfLogger = l
	go b.bpfLogger.Read()
	return nil
}

func (b *bpfLoggerExtension) Shutdown(ctx context.Context) error {
	if b.bpfLogger == nil {
		return nil
	}
	b.bpfLogger.Stop()
	return nil
}
