package procexec

func Objects() procexecObjects {
	return procexecObjects{}
}

type ProcexecObjects struct {
	Obj procexecObjects
}

func LoadObjects() (ProcexecObjects, error) {
	objs := procexecObjects{}
	if err := loadProcexecObjects(&objs, nil); err != nil {
		return ProcexecObjects{}, err
	}
	return ProcexecObjects{
		Obj: objs,
	}, nil
}

type ProcexecEvent struct {
	procexecEvent
}
