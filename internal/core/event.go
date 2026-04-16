package core

import "time"

type Event struct {
	// Common fields
	EventType string    `json:"event_type"` // "connection" for connection events
	Timestamp time.Time `json:"timestamp"`

	// Network related fields
	SrcContainer   *ContainerInfo `json:"src_container,omitempty"`
	SrcProcessName string         `json:"src_process_name,omitempty"`
	SrcPID         uint32         `json:"src_pid,omitempty"`
	SrcCgroupID    uint64         `json:"src_cgroup_id,omitempty"`
	SrcAddr        string         `json:"src_addr,omitempty"`
	SrcPort        uint16         `json:"src_port,omitempty"`

	DstContainer   *ContainerInfo `json:"dst_container,omitempty"`
	DstProcessName string         `json:"dst_process_name,omitempty"`
	DstPID         uint32         `json:"dst_pid,omitempty"`
	DstCgroupID    uint64         `json:"dst_cgroup_id,omitempty"`
	DstAddr        string         `json:"dst_addr,omitempty"`
	DstPort        uint16         `json:"dst_port,omitempty"`

	// File related fields
	FilePath string `json:"file_path,omitempty"`
	FileOp   string `json:"file_op,omitempty"`

	// Exec related fields
	ExecPath          string `json:"exec_path,omitempty"`
	ParentPID         uint32 `json:"parent_pid,omitempty"`
	ParentProcessName string `json:"parent_process_name,omitempty"`
}
