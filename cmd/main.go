package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lmittmann/tint"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
	"github.com/ArturLukianov/eBPF-monitor/internal/correlator"
	bpf "github.com/ArturLukianov/eBPF-monitor/internal/ebpf"
	"github.com/ArturLukianov/eBPF-monitor/internal/output"
	"github.com/ArturLukianov/eBPF-monitor/internal/resolver"
	"github.com/ArturLukianov/eBPF-monitor/internal/ruleengine"
)

var filterPrefixArg string
var debugArg bool
var rulesFolderArg string

func init() {
	// Parse flags
	flag.StringVar(&filterPrefixArg, "filter-prefix", "", "Prefix filter for container names")
	flag.StringVar(&rulesFolderArg, "rules", "./rules", "Folder with alert rules (*.yaml)")
	flag.BoolVar(&debugArg, "debug", false, "Enable debug mode")
	flag.Parse()

	// Setup logger
	logLevel := slog.LevelInfo
	if debugArg {
		logLevel = slog.LevelDebug
	}

	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level: logLevel,
		}),
	))

	// According to https://pkg.go.dev/github.com/cilium/ebpf/rlimit, it should be invoked once
	// This basically does nothing on kernels 5.11+ , but it is required for older ones
	err := rlimit.RemoveMemlock()
	if err != nil {
		slog.Error("could not remove memlock", "error", err)
	}
}

func main() {
	// Setup engine
	engine := ruleengine.New(rulesFolderArg)
	if engine == nil {
		slog.Error("could not create engine")
		os.Exit(-1)
	}

	// Load compiled eBPF
	objs := bpf.MonitorObjects{}
	err := bpf.LoadMonitorObjects(&objs, nil)

	if err != nil {
		slog.Error("could not load objects", "error", err.Error())
		os.Exit(-1)
	}
	defer objs.Close()

	// Attach kprobes
	kpTcpConnect, err := link.Kprobe("tcp_connect", objs.TcpConnect, nil)
	if err != nil {
		slog.Error("could not attach kprobe tcp_connect", "error", err.Error())
		os.Exit(-1)
	}
	defer kpTcpConnect.Close()

	kpInetCskAccept, err := link.Kretprobe("inet_csk_accept", objs.InetCskAccept, nil)
	if err != nil {
		slog.Error("could not attach kprobe inet_csk_accept", "error", err.Error())
		os.Exit(-1)
	}
	defer kpInetCskAccept.Close()

	// Setup resolver
	resolver, err := resolver.New()
	if err != nil {
		slog.Error("could not create resolver", "error", err.Error())
		os.Exit(-1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go resolver.MonitorEventsLoop(ctx)

	// Setup correlator
	corr := correlator.New(time.Second * 5)

	// Fan out + Filter + Enrich events to output and rule engine
	outputCh := make(chan core.Event, 1024)
	engineCh := make(chan core.Event, 1024)

	go func() {
		for event := range corr.Output() {
			srcInfo := resolver.Resolve(event.SrcCgroupID)
			dstInfo := resolver.Resolve(event.DstCgroupID)

			// If container not found, skip
			if srcInfo == nil || dstInfo == nil {
				continue
			}

			// If filter is set, drop not matching connections
			if filterPrefixArg != "" {
				if !strings.HasPrefix(srcInfo.Name, filterPrefixArg) &&
					!strings.HasPrefix(dstInfo.Name, filterPrefixArg) {
					continue
				}
			}

			event.SrcContainer = *srcInfo
			event.DstContainer = *dstInfo

			outputCh <- event
			engineCh <- event
		}
	}()

	alertsCh := engine.Alerts()

	// Setup output
	go output.OutputLoop(outputCh, alertsCh)
	go engine.ProcessLoop(engineCh)

	slog.Info("eBPF-monitor started")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("could not open ringbuf reader", "error", err.Error())
		os.Exit(-1)
	}
	defer rd.Close()

	// Close ringbuffer on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
		corr.Close()
		cancel()
		close(engineCh)
		close(outputCh)
	}()

	// Read events from ringbuffer

	for {
		record, err := rd.Read()
		if err != nil {
			slog.Error("ringbuf read error", "error", err.Error())
			os.Exit(-1)
		}

		event := bpf.ParseEvent(record.RawSample)
		if event == nil {
			continue
		}

		switch event.EventType {
		case bpf.EVENT_CONNECT:
			corr.HandleConnect(
				event.SrcAddr, event.SrcPort,
				event.DstAddr, event.DstPort,
				event.CgroupId, event.Pid, event.Comm)
		case bpf.EVENT_ACCEPT:
			corr.HandleAccept(
				event.SrcAddr, event.SrcPort,
				event.DstAddr, event.DstPort,
				event.CgroupId, event.Pid, event.Comm)
		}
	}
}
