package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ArturLukianov/eBPF-monitor/internal/correlator"
	bpf "github.com/ArturLukianov/eBPF-monitor/internal/ebpf"
)

func init() {
	// According to https://pkg.go.dev/github.com/cilium/ebpf/rlimit, it should be invoked once
	// This basically does nothing on kernels 5.11+ , but it is required for older ones
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatalf("could not remove memlock: %v", err)
	}
}

func main() {
	// Load compiled eBPF
	objs := bpf.MonitorObjects{}
	err := bpf.LoadMonitorObjects(&objs, nil)

	if err != nil {
		log.Fatalf("could not load objects: %v", err)
	}
	defer objs.Close()

	// Attach kprobes
	kpTcpConnect, err := link.Kprobe("tcp_connect", objs.TcpConnect, nil)
	if err != nil {
		log.Fatalf("could not attach kprobe tcp_connect: %v", err)
	}
	defer kpTcpConnect.Close()

	kpInetCskAccept, err := link.Kretprobe("inet_csk_accept", objs.InetCskAccept, nil)
	if err != nil {
		log.Fatalf("could not attach kprobe inet_csk_accept: %v", err)
	}
	defer kpInetCskAccept.Close()

	// Setup correlator
	corr := correlator.New(time.Second * 5)

	// Setup logger
	go func() {
		for connEntry := range corr.Output() {
			// Output event
			fmt.Printf("[EVENT]: CONNECT pid=%d cgroup=%d %s:%d -> pid=%d cgroup=%d %s:%d\n",
				connEntry.SrcPID,
				connEntry.SrcCgroupID,
				connEntry.SrcAddr,
				connEntry.SrcPort,

				connEntry.DstPID,
				connEntry.DstCgroupID,
				connEntry.DstAddr,
				connEntry.DstPort,
			)
		}
	}()

	log.Println("eBPF-monitor started")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("could not open ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Close ringbuffer on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
		corr.Close()
	}()

	// Read events from ringbuffer

	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("ringbuf read error: %v", err)
			return
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
