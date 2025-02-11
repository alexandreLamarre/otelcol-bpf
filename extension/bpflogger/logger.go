package bpflogger

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

type bpfLogger struct {
	pipe   *os.File
	stopC  chan struct{}
	logger *zap.Logger

	// for testing, shutdown should wait until the pipe is closed
	closed chan struct{}
}

func (b *bpfLogger) Read() {
	defer func() {
		if err := b.pipe.Close(); err != nil {
			b.logger.Error(fmt.Sprintf("failed to close bpf trace pipe : %s", err))
		}
	}()
	reader := bufio.NewReader(b.pipe)
	b.logger.Info("Starting read from BPF pipe...")
	for {
		select {
		case <-b.stopC:
			b.logger.Info("Stopping read from BPF pipe...")
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				b.logger.Error(fmt.Sprintf("failed to read from BPF pipe : %s", err))
			}
			if len(line) == 1 || strings.TrimSpace(line) == "" {
				continue
			}
			line = line[:len(line)-1]
			// TODO : add structure logging based on receiver, and extract them via regex here
			b.logger.Info(line)
		}
	}
}

func (b *bpfLogger) Stop() {
	b.stopC <- struct{}{}
	close(b.stopC)
}

func newBpfLogger(path string, logger *zap.Logger) (*bpfLogger, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &bpfLogger{
		pipe:   file,
		logger: logger,
		stopC:  make(chan struct{}, 1),
		closed: make(chan struct{}, 1),
	}, nil
}
