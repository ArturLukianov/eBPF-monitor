.PHONY: generate build clean

generate:
	go generate ./...

build: generate
	go build -o bin/ebpf-monitor ./cmd

clean:
	rm -f bin/monitor
	rm -f internal/ebpf/monitor_bpf*.go
	rm -f internal/ebpf/monitor_bpf*.o

run: build
	sudo ./bin/monitor