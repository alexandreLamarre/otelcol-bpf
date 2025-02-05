//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I ../../../../include/vmlinux -I ../../../../include/libbpf  -I procexec.h" procexec procexec.bpf.c
package bpf
