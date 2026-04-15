package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ArturLukianov/eBPF-monitor/internal/correlator"
	"github.com/ArturLukianov/eBPF-monitor/internal/resolver"
)

type StructuredOutput struct {
	Type      string `json:"type"`       // "event" for events
	EventType string `json:"event_type"` // "connection" for connection events

	// Connection event data
	Data struct {
		SrcContainer   string `json:"src_container"`
		SrcProcessName string `json:"src_process_name"`
		SrcPID         uint32 `json:"src_pid"`
		SrcCgroupID    uint64 `json:"src_cgroup_id"`
		SrcAddr        string `json:"src_addr"`
		SrcPort        uint16 `json:"src_port"`

		DstContainer   string `json:"dst_container"`
		DstProcessName string `json:"dst_process_name"`
		DstPID         uint32 `json:"dst_pid"`
		DstCgroupID    uint64 `json:"dst_cgroup_id"`
		DstAddr        string `json:"dst_addr"`
		DstPort        uint16 `json:"dst_port"`
	} `json:"data"`
}

func OutputLoop(chanEntry <-chan correlator.ConnectionEntry, resolver *resolver.Resolver, filterPrefix string) {
	for connEntry := range chanEntry {
		srcInfo := resolver.Resolve(connEntry.SrcCgroupID)
		dstInfo := resolver.Resolve(connEntry.DstCgroupID)

		// If container not found, skip
		if srcInfo == nil || dstInfo == nil {
			continue
		}

		// If filter is set, drop not matching connections
		if filterPrefix != "" {
			if !strings.HasPrefix(srcInfo.Name, filterPrefix) &&
				!strings.HasPrefix(dstInfo.Name, filterPrefix) {
				continue
			}
		}

		slog.Debug("New event", "event", "connection",
			"srcContainer", srcInfo.Name,
			"srcPID", connEntry.SrcPID,
			"srcCgroupID", connEntry.SrcCgroupID,
			"srcAddr", connEntry.SrcAddr,
			"srcPort", connEntry.SrcPort,

			"dstContainer", dstInfo.Name,
			"dstPID", connEntry.DstPID,
			"dstCgroupID", connEntry.DstCgroupID,
			"dstAddr", connEntry.DstAddr,
			"dstPort", connEntry.DstPort,
		)

		// Output event

		var out StructuredOutput

		out.Type = "event"
		out.EventType = "connection"
		out.Data.SrcContainer = srcInfo.Name
		out.Data.DstContainer = dstInfo.Name
		out.Data.SrcAddr = connEntry.SrcAddr
		out.Data.DstAddr = connEntry.DstAddr
		out.Data.SrcPort = connEntry.SrcPort
		out.Data.DstPort = connEntry.DstPort

		eventData, err := json.Marshal(out)
		if err != nil {
			slog.Error("Failed to marshal event", "error", err)
			continue
		}

		fmt.Println(string(eventData)) // TODO: Maybe direct write to stdout?
	}
}
