package ebpf

// the target is set to be x86

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" Monitor ../../bpf/monitor.c -- -I../../bpf/headers
