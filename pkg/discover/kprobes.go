package discover

import (
	"bufio"
	"errors"
	"os"
	"path"
	"strings"
)

type kprobes struct {
	debugFsPath string
	kallSyms    *os.File
	blackList   *os.File
	registered  *os.File
}

type registeredKprobe struct {
	KernelAddress string
	ProbeType     string
	ProbeName     string
	ProbeStatus   string
}

type KProbeInfo struct {
	Address string
	Type    string
	Name    string
	// TODO : look at the format of registered kprobes
	Registered bool
}

// function name -> address range
type kprobeBlacklist map[string]string

type registerKprobeList map[string]registeredKprobe

var _ Discoverer[KProbeInfo] = (*kprobes)(nil)

func NewKprobes(
	debugFsPath string,
) Discoverer[KProbeInfo] {
	return &kprobes{
		debugFsPath: debugFsPath,
	}
}

func (k *kprobes) Start() error {
	registerdProbesPath := path.Join(k.debugFsPath, "kprobes/list")
	if _, err := os.Stat(registerdProbesPath); err != nil {
		return err
	}
	fRegisterd, err := os.Open(registerdProbesPath)
	if err != nil {
		return err
	}
	k.registered = fRegisterd
	if _, err := os.Stat("/proc/kallsyms"); err != nil {
		return err
	}
	fKallsyms, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	k.kallSyms = fKallsyms
	blackList := path.Join(k.debugFsPath, "kprobes/blacklist")
	if _, err := os.Stat("/sys/kernel/debug/kprobes/blacklist"); err != nil {
		return err
	}
	fBlackList, err := os.Open(blackList)
	if err != nil {
		return err
	}
	k.blackList = fBlackList
	return nil
}

func (k *kprobes) Discovery(filterFunc func(KProbeInfo) bool) ([]KProbeInfo, error) {
	scannerReg := bufio.NewScanner(k.registered)
	registered := registerKprobeList{}
	for scannerReg.Scan() {
		line := scannerReg.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue // invalid entry
		}
		loadedComponents := strings.Split(fields[2], "+")
		probeName := loadedComponents[0]
		info := registeredKprobe{
			KernelAddress: fields[0],
			ProbeType:     fields[1],
			ProbeStatus:   "[RUNNING]",
		}

		if len(fields) > 3 {
			info.ProbeStatus = fields[3]
		}
		registered[probeName] = info
	}

	scannerBlackList := bufio.NewScanner(k.blackList)
	blacklist := kprobeBlacklist{}
	for scannerBlackList.Scan() {
		line := scannerBlackList.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		blacklist[fields[1]] = fields[0]
	}

	ret := []KProbeInfo{}
	scannerKallsyms := bufio.NewScanner(k.kallSyms)
	for scannerKallsyms.Scan() {
		line := scannerKallsyms.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 { // invalid entry
			continue
		}
		info := KProbeInfo{
			Address: fields[0],
			Type:    fields[1],
			Name:    fields[2],
		}
		if _, ok := registered[info.Name]; ok {
			info.Registered = true
		}
		if _, ok := blacklist[info.Name]; !ok {
			ret = append(ret, info)
		}
	}
	return ret, nil
}

func (k *kprobes) Shutdown() error {
	errs := []error{
		k.removeRegistered(),
		k.removeKallsyms(),
		k.removeBlackList(),
	}
	return errors.Join(errs...)
}

func (k *kprobes) removeRegistered() error {
	if k.registered == nil {
		return nil
	}
	if err := k.registered.Close(); err != nil {
		return err
	}
	return nil
}

func (k *kprobes) removeKallsyms() error {
	if k.kallSyms == nil {
		return nil
	}
	if err := k.kallSyms.Close(); err != nil {
		return err
	}
	return nil
}

func (k *kprobes) removeBlackList() error {
	if k.blackList == nil {
		return nil
	}
	if err := k.blackList.Close(); err != nil {
		return err
	}
	return nil
}
