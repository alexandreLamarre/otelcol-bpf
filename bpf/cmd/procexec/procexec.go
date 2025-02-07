package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/alexandreLamarre/otelcol-bpf/bpf/pkg/byteutil"
	"github.com/alexandreLamarre/otelcol-bpf/bpf/procexec"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func BuildProcExecCommand() *cobra.Command {
	var collectFor time.Duration
	var outputFormat string
	cmd := &cobra.Command{
		Use: "procexec",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains([]string{"log", "logs"}, outputFormat) {
				return fmt.Errorf("unsupported log format : %s", outputFormat)
			}
			ctx, ca := context.WithTimeout(cmd.Context(), collectFor)
			defer ca()
			events := run(ctx)
			w := table.NewWriter()
			if strings.HasPrefix(outputFormat, "log") {
				header := []any{"COMM", "PPID", "PID", "UID", "ELAPSED (ns)"}
				w.AppendHeader(header)

				for _, e := range events {
					w.AppendRow(table.Row{byteutil.CCharSliceToStr(e.Comm[:]), e.Ppid, e.Pid, e.Uid, e.Elapsed})
				}
			}

			cmd.Println(w.Render())
			return nil
		},
	}
	cmd.Flags().DurationVarP(&collectFor, "for", "t", 10*time.Second, "run procexec for the amount of specified seconds")
	cmd.Flags().StringVarP(&outputFormat, "fmt", "", "log", "output format to print to stdout")
	return cmd
}

func readPerfEvent(buf *bytes.Buffer, event *procexec.ProcexecEvent) error {
	// Read the basic integer fields first (without Comm and Args)
	err := binary.Read(buf, binary.LittleEndian, &event.Pid)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.Ppid)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.Uid)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.Retval)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.ArgsCount)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.ArgsSize)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.StartTime)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &event.Elapsed)
	if err != nil {
		return err
	}
	// Now handle reading Comm (null-terminated string)
	if err := byteutil.ReadNullTerminatedString(buf, event.Comm[:]); err != nil {
		return err
	}

	// Finally, handle reading Args (null-terminated string)
	if err := byteutil.ReadNullTerminatedString(buf, event.Args[:]); err != nil {
		return err
	}
	return nil
}

func run(ctx context.Context) []procexec.ProcexecEvent {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove rlimit : %s", err)
	}

	objs, err := procexec.LoadObjects()
	if err != nil {
		log.Fatalf("loading proc exec events : %s", err)
	}

	procExec, err := link.Tracepoint("sched", "sched_process_exec", objs.Obj.SchedSchedProcessExec, nil)
	if err != nil {
		log.Fatalf("failed to start sys_exit_execve kprobe : %s", err)
	}
	defer procExec.Close()

	procExit, err := link.Tracepoint("sched", "sched_process_exit", objs.Obj.SchedSchedProcessExit, nil)
	if err != nil {
		log.Fatalf("failed to start sys_exit_execve kprobe : %s", err)
	}
	defer procExit.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	rd, err := perf.NewReader(objs.Obj.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader : %s", err)
	}
	defer rd.Close()
	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		select {
		case <-stopper:
		case <-ctx.Done():
		}
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	log.Println("waiting for events")
	allEvents := []procexec.ProcexecEvent{}
	for {
		select {
		case <-ctx.Done():
			return allEvents
		default:
		}
		record, err := rd.Read()
		if errors.Is(err, perf.ErrClosed) {
			return allEvents
		}
		if err != nil {
			log.Printf("failed to read from perf buffer array : %s", err)
		}

		if record.LostSamples != 0 {
			log.Printf("perf event buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		var event procexec.ProcexecEvent
		if err := readPerfEvent(bytes.NewBuffer(record.RawSample), &event); err != nil {
			log.Println("Got error while reading perf event : ", err)
			continue
		}
		allEvents = append(allEvents, event)
	}
}

func main() {
	cmd := BuildProcExecCommand()
	if err := cmd.Execute(); err != nil {
		log.Println(err)
	}
}
