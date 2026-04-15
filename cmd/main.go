package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lmittmann/tint"

	"github.com/ArturLukianov/eBPF-monitor/internal/correlator"
	bpf "github.com/ArturLukianov/eBPF-monitor/internal/ebpf"
	"github.com/ArturLukianov/eBPF-monitor/internal/output"
	"github.com/ArturLukianov/eBPF-monitor/internal/resolver"
)

var filterPrefixArg string

func init() {
	// Parse flags
	flag.StringVar(&filterPrefixArg, "filter-prefix", "", "Prefix filter for container names")
	flag.Parse()

	// Setup logger
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level: slog.LevelDebug,
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
	}
	ctx, cancel := context.WithCancel(context.Background())
	go resolver.MonitorEvents(ctx)

	// Setup correlator
	corr := correlator.New(time.Second * 5)

	// Setup output
	go output.OutputLoop(corr.Output(), resolver, filterPrefixArg)

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
				event.CgroupId, event.Pid)
		case bpf.EVENT_ACCEPT:
			corr.HandleAccept(
				event.SrcAddr, event.SrcPort,
				event.DstAddr, event.DstPort,
				event.CgroupId, event.Pid)
		}
	}
}
