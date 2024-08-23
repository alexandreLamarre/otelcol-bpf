package discover

import (
	"bufio"
	"os"
	"strings"
)

type MountInfo struct {
	Device     string
	MountPoint string
	FSType     string
	Options    string
}

type mountChecker struct {
	mount *os.File
}

var _ Discoverer[MountInfo] = (*mountChecker)(nil)

func NewMountChecker() Discoverer[MountInfo] {
	return &mountChecker{}
}

func (m *mountChecker) Start() error {
	if _, err := os.Stat("/proc/mounts"); err != nil {
		return err
	}

	f, err := os.Open("/proc/mounts")
	if err != nil {
		return err
	}

	m.mount = f
	return nil
}

func (m *mountChecker) Discovery(filterFunc func(MountInfo) bool) ([]MountInfo, error) {
	scanner := bufio.NewScanner(m.mount)
	mounts := []MountInfo{}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue // ignore malformed mount fields
		}
		mount := MountInfo{
			Device:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    fields[3],
		}
		if filterFunc(mount) {
			mounts = append(mounts, mount)
		}
	}
	return mounts, nil
}

func (m *mountChecker) Shutdown() error {
	if m.mount == nil {
		return nil
	}
	if err := m.mount.Close(); err != nil {
		return err
	}
	return nil
}
