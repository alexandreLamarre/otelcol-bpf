package bpfutil

import (
	"sync"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/util"
	"github.com/cilium/ebpf/rlimit"
)

var (
	removeMemlock = memLockRemover{
		mu: &sync.RWMutex{},
	}
)

type memLockRemover struct {
	util.Initializer
	removeErr error
	mu        *sync.RWMutex
}

func RemoveMemlock() error {
	removeMemlock.InitOnce(func() {
		removeMemlock.mu.Lock()
		defer removeMemlock.mu.Unlock()
		removeMemlock.removeErr = rlimit.RemoveMemlock()
	})

	removeMemlock.WaitForInit()
	return removeMemlock.removeErr

}
