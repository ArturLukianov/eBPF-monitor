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

// 	/* size: 48, cachelines: 1, members: 8 */
// 	/* sum members: 33, holes: 3, sum holes: 9 */
// 	/* padding: 6 */
// 	/* last cacheline: 48 bytes */
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
}

// Event types
const (
	EVENT_CONNECT = 1
	EVENT_ACCEPT  = 2
	EVENT_CLOSE   = 3
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
