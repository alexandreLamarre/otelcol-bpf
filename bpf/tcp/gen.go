//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I ../include  -I ./tcpconnlat.h" tcpconnlat tcpconnlat.bpf.c
package tcp
