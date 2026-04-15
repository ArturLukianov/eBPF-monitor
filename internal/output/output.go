package output

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
)

type StructuredOutput struct {
	Type string `json:"type"` // "event" for events, "alert" for alerts

	Event core.Event `json:"event,omitempty"`
	Alert core.Alert `json:"alert,omitempty"`
}

func OutputLoop(eventCh <-chan core.Event, alertCh <-chan core.Alert) {
	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				eventCh = nil
				continue
			}

			slog.Debug("New event", "event", "connection",
				"srcContainer", event.SrcContainer.Name,
				"srcPID", event.SrcPID,
				"srcProcessName", event.SrcProcessName,
				"srcCgroupID", event.SrcCgroupID,
				"srcAddr", event.SrcAddr,
				"srcPort", event.SrcPort,

				"dstContainer", event.DstContainer.Name,
				"dstPID", event.DstPID,
				"dstProcessName", event.DstProcessName,
				"dstCgroupID", event.DstCgroupID,
				"dstAddr", event.DstAddr,
				"dstPort", event.DstPort,
			)

			// Output event

			var out StructuredOutput

			out.Type = "event"
			out.Event = event

			eventData, err := json.Marshal(out)
			if err != nil {
				slog.Error("Failed to marshal event", "error", err)
				continue
			}

			fmt.Println(string(eventData)) // TODO: Maybe direct write to stdout?
		case alert, ok := <-alertCh:
			if !ok {
				alertCh = nil
				continue
			}

			slog.Warn("New alert", "alert", alert)

			var out StructuredOutput
			out.Type = "alert"
			out.Alert = alert

			alertData, err := json.Marshal(out)
			if err != nil {
				slog.Error("Failed to marshal alert", "error", err)
				continue
			}

			fmt.Println(string(alertData)) // TODO: Maybe direct write to stdout?
		}

		if eventCh == nil && alertCh == nil {
			// Exit if both channels are closed
			return
		}
	}
}
