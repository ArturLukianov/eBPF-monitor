package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
	// bpf "github.com/ArturLukianov/internal/ebpf"
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
}
