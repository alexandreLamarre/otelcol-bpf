//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I ../include  -I ./procexec.h" procexec procexec.bpf.c
package procexec
