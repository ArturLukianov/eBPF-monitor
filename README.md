# eBPF monitor

A lightweight tool for monitoring inter-container interaction for detecting lateral movement attacks.

This tool requires eBPF to run. You can check that eBPF is available by running:

```bash
ls /sys/kernel/btf/vmlinux
```

Generate required headers (optional):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
```

Build:

```bash
make build
```

Run:

```bash
sudo ./bin/ebpf-monitor
```
