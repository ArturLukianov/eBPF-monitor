package core

import "time"

type Alert struct {
	Timestamp   time.Time `json:"timestamp"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`

	SrcContainer *ContainerInfo `json:"src_container"` // May be nil if it is only container attack
	DstContainer *ContainerInfo `json:"dst_container"`
}
