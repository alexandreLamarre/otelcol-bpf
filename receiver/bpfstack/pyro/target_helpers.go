//go:build linux

package pyro

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
)

type RelabelConfig struct {
	SourceLabels []string
	Separator    string
	Regex        string
	TargetLabel  string `yaml:"target_label,omitempty"`
	Replacement  string `yaml:"replacement,omitempty"`
	Action       string
}

type Config struct {
	TargetsOptions sd.TargetsOptions
	RelabelConfig  []*RelabelConfig
	SessionOptions ebpfspy.SessionOptions
}

func convertTargetOptions(logger log.Logger, config *Config) sd.TargetsOptions {
	targets := relabelProcessTargets(getProcessTargets(logger), config.RelabelConfig)
	o := config.TargetsOptions
	o.Targets = targets
	return o
}

func relabelProcessTargets(targets []sd.DiscoveryTarget, cfg []*RelabelConfig) []sd.DiscoveryTarget {
	var promConfig []*relabel.Config
	for _, c := range cfg {
		var srcLabels model.LabelNames
		for _, label := range c.SourceLabels {
			srcLabels = append(srcLabels, model.LabelName(label))
		}
		promConfig = append(promConfig, &relabel.Config{
			SourceLabels: srcLabels,
			Separator:    c.Separator,
			Regex:        relabel.MustNewRegexp(c.Regex),
			TargetLabel:  c.TargetLabel,
			Replacement:  c.Replacement,
			Action:       relabel.Action(c.Action),
		})
	}
	var res []sd.DiscoveryTarget
	for _, target := range targets {
		lbls := labels.FromMap(target)
		lbls, keep := relabel.Process(lbls, promConfig...)

		if !keep {
			continue
		}
		tt := sd.DiscoveryTarget(lbls.Map())
		res = append(res, tt)
	}
	return res
}

func getProcessTargets(logger log.Logger) []sd.DiscoveryTarget {
	dir, err := os.ReadDir("/proc")
	if err != nil {
		panic(err)
	}
	var res []sd.DiscoveryTarget
	for _, entry := range dir {
		if !entry.IsDir() {
			continue
		}
		spid := entry.Name()
		pid, err := strconv.ParseUint(spid, 10, 32)
		if err != nil {
			continue
		}
		if pid == 0 {
			continue
		}
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%s/cwd", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading cwd", "pid", spid)
			}
			continue
		}
		cwd = strings.TrimSpace(cwd)

		exe, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading exe", "pid", spid)
			}
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading comm", "pid", spid)
			}
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading cmdline", "pid", spid)
			}
		} else {
			cmdline = bytes.ReplaceAll(cmdline, []byte{0}, []byte(" "))
		}
		target := sd.DiscoveryTarget{
			"__process_pid__": spid,
			"cwd":             cwd,
			"comm":            strings.TrimSpace(string(comm)),
			"pid":             spid,
			"exe":             exe,
			"service_name":    fmt.Sprintf("%s @ %s", cmdline, cwd),
		}
		res = append(res, target)
	}
	return res
}
