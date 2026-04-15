.PHONY: generate build clean

generate:
	go generate ./...

build: generate
	go build -o bin/ebpf-monitor ./cmd

clean:
	rm -f bin/monitor
	rm -f internal/ebpf/monitor_bpf*.go
	rm -f internal/ebpf/monitor_bpf*.o

show-event-struct:
	clang -g -O2 -D__TARGET_ARCH_x86 -target bpf -c bpf/monitor.c -o /tmp/debug.o -I bpf/headers
	pahole -C event /tmp/debug.o

run: build
	sudo ./bin/monitor