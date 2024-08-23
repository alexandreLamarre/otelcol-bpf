package discover_test

import (
	"testing"

	"github.com/alexandreLamarre/otelbpf/pkg/discover"
	"github.com/stretchr/testify/assert"
)

func TestKprobe(t *testing.T) {
	m := discover.NewMountChecker()
	err := m.Start()
	assert.Nil(t, err)
	debugMounts, err := m.Discovery(func(info discover.MountInfo) bool {
		return info.Device == "debugfs"
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, debugMounts)

	err = m.Shutdown()
	assert.Nil(t, err)

	k := discover.NewKprobes(debugMounts[0].MountPoint)
	err = k.Start()
	assert.Nil(t, err)

	probes, err := k.Discovery(func(probe discover.KProbeInfo) bool {
		return true
	})
	assert.Nil(t, err)
	assert.NotEmpty(t, probes)

	for _, p := range probes {
		t.Log(p)
	}

	err = k.Shutdown()
	assert.Nil(t, err)
}
