//go:build ignore
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

enum event_type : __u8 {
    EVENT_CONNECT = 1,
    EVENT_ACCEPT = 2,
    EVENT_CLOSE = 3
};

// Event passed to ring buffer
struct event { 
    // Common fields
    __u32 pid;
    __u64 cgroup_id;
    __u64 timestamp; // Unix timestamp in nanoseconds
    enum event_type event_type;

    // Event-specific fields (possibly make a union later to save space)
    __u32 src_addr;
    __u16 src_port;
    __u32 dst_addr;
    __u16 dst_port;

    char comm[16];
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// Helpers

void fill_common_fields(struct event *event, enum event_type type) {
    if (!event) return;

    event->event_type = type;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = bpf_get_current_cgroup_id(); // This value is actually inode number of cgroup v2 directory
    event->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// tcp_connect - outgoing connections
SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk) {
    struct event *event;

    if (!sk) return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2) return 0; // Only process IPv4 (AF_INET = 2)

    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0; // TODO: Handle error

    // Fill common fields
    fill_common_fields(event, EVENT_CONNECT);

    // SRC -[tcp_connect]-> DST
    event->src_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dst_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_dport));


    bpf_ringbuf_submit(event, 0);

    return 0;
}

// inet_csk_accept - incoming connections
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *sk) {
    struct event *event;

    if (!sk) return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2) return 0; // Only process IPv4 (AF_INET = 2)

    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0; // TODO: Handle error

    fill_common_fields(event, EVENT_ACCEPT);

    // DST -[inet_csk_accept]-> SRC
    event->src_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dst_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";