package core

import "time"

type Event struct {
	EventType string `json:"event_type"` // "connection" for connection events

	Timestamp time.Time `json:"timestamp"`

	SrcContainer   ContainerInfo `json:"src_container"`
	SrcProcessName string        `json:"src_process_name"`
	SrcPID         uint32        `json:"src_pid"`
	SrcCgroupID    uint64        `json:"src_cgroup_id"`
	SrcAddr        string        `json:"src_addr"`
	SrcPort        uint16        `json:"src_port"`

	DstContainer   ContainerInfo `json:"dst_container"`
	DstProcessName string        `json:"dst_process_name"`
	DstPID         uint32        `json:"dst_pid"`
	DstCgroupID    uint64        `json:"dst_cgroup_id"`
	DstAddr        string        `json:"dst_addr"`
	DstPort        uint16        `json:"dst_port"`
}
