package ebpf

import (
	"bytes"
	"encoding/binary"
)

// if this struct in "monitor.c" is changed, this file should be changed too
// TODO: think about how to deal with padding

// struct event {
// 	__u32                      pid;                  /*     0     4 */

// 	/* XXX 4 bytes hole, try to pack */

// 	__u64                      cgroup_id;            /*     8     8 */
// 	__u64                      timestamp;            /*    16     8 */
// 	enum event_type            event_type;           /*    24     1 */

// 	/* XXX 3 bytes hole, try to pack */

// 	__u32                      src_addr;             /*    28     4 */
// 	__u16                      src_port;             /*    32     2 */

// 	/* XXX 2 bytes hole, try to pack */

// 	__u32                      dst_addr;             /*    36     4 */
// 	__u16                      dst_port;             /*    40     2 */
// 	char                       comm[16];             /*    42    16 */
// 	char                       filepath[256];        /*    58   256 */

// 	/* XXX 2 bytes hole, try to pack */

// 	/* --- cacheline 4 boundary (256 bytes) was 60 bytes ago --- */
// 	__u32                      ppid;                 /*   316     4 */
// 	/* --- cacheline 5 boundary (320 bytes) --- */
// 	char                       parent_comm[16];      /*   320    16 */
// 	__u32                      flags;                /*   336     4 */

// 	/* size: 344, cachelines: 6, members: 13 */
// 	/* sum members: 329, holes: 4, sum holes: 11 */
// 	/* padding: 4 */
// 	/* last cacheline: 24 bytes */
// };

type MonitorEvent struct {
	Pid       uint32
	Pad1      [4]byte
	CgroupId  uint64
	Timestamp uint64
	EventType uint8
	Pad2      [3]byte

	SrcAddr uint32
	SrcPort uint16
	Pad3    [2]byte
	DstAddr uint32
	DstPort uint16

	Comm [16]byte

	Filepath   [256]byte
	Pad4       [2]byte
	Ppid       uint32
	ParentComm [16]byte
	Flags      uint32
}

// Event types
const (
	EVENT_NET_CONNECT = 1
	EVENT_NET_ACCEPT  = 2
	EVENT_NET_CLOSE   = 3
	EVENT_FILE_OPEN   = 4
	EVENT_EXEC        = 5
)

func ParseEvent(data []byte) *MonitorEvent {
	var event MonitorEvent

	if len(data) < binary.Size(event) {
		return nil
	}

	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	if err != nil {
		return nil
	}
	return &event
}
