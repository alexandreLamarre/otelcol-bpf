//go:generate go run go.opentelemetry.io/collector/cmd/mdatagen metadata.yaml

// Package bpflogger adds (structured) logging for bpf_printk debug logs in the otel collector bpf distribution
package bpflogger
