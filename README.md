# eBPF monitor

A lightweight tool for monitoring inter-container interaction for detecting lateral movement attacks.

This tool requires eBPF to run. You can check that eBPF is available by running:

```bash
ls /sys/kernel/btf/vmlinux
```

Build:

```bash
make build
```

Run:

```bash
sudo ./bin/ebpf-monitor
```
