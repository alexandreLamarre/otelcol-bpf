package discover_test

import (
	"testing"

	"github.com/alexandreLamarre/otelbpf/pkg/discover"
	"github.com/stretchr/testify/assert"
)

func TestMountChecker(t *testing.T) {
	m := discover.NewMountChecker()
	err := m.Start()
	assert.Nil(t, err)
	isDebugFsMounted := func(info discover.MountInfo) bool {
		return info.Device == "debugfs"
	}
	mounts, err := m.Discovery(isDebugFsMounted)
	assert.Nil(t, err)
	assert.NotEmpty(t, mounts)

	err = m.Shutdown()
	assert.Nil(t, err)
}
