package ruleengine

import (
	"path"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
)

type MatchBlock struct {
	EventType string `yaml:"event_type"`

	SrcProcess   string   `yaml:"src_process"`
	DstProcess   string   `yaml:"dst_process"`
	SrcContainer string   `yaml:"src_container"`
	DstContainer string   `yaml:"dst_container"`
	SrcPort      PortExpr `yaml:"src_port"`
	DstPort      PortExpr `yaml:"dst_port"`

	FilePath string `yaml:"file_path"`
	FileOp   string `yaml:"file_op"`

	ExecPath      string `yaml:"exec_path"`
	ParentProcess string `yaml:"parent_process"`

	Not *MatchBlock
}

type DetectConfig struct {
	Mode    string // "single" or "threshold" (for bruteforce like events)
	Count   int
	Window  string
	GroupBy []string `yaml:"group_by"`
}

type Rule struct {
	Name        string
	Description string
	Severity    string
	Mitre       string
	Match       *MatchBlock
	Any         []MatchBlock // OR logic
	All         []MatchBlock // AND logic
	Detect      DetectConfig

	Sequence *SequenceConfig `yaml:"sequence"`
}

func matchPattern(pattern, value string) bool {
	matched, err := path.Match(pattern, value)
	if err != nil {
		return false
	}
	return matched
}

func (m *MatchBlock) MatchEvent(event core.Event) bool {
	if m.Not != nil {
		return !m.Not.MatchEvent(event)
	}

	if m.EventType != "" && m.EventType != string(event.EventType) {
		return false
	}

	res := true

	if m.SrcProcess != "" {
		res = res && matchPattern(m.SrcProcess, event.SrcProcessName)
	}
	if m.DstProcess != "" {
		res = res && matchPattern(m.DstProcess, event.DstProcessName)
	}
	if m.SrcContainer != "" && event.SrcContainer != nil {
		res = res && matchPattern(m.SrcContainer, event.SrcContainer.Name)
	}
	if m.DstContainer != "" && event.DstContainer != nil {
		res = res && matchPattern(m.DstContainer, event.DstContainer.Name)
	}

	if !m.SrcPort.IsZero() && event.SrcPort != 0 {
		res = res && m.SrcPort.Match(event.SrcPort)
	}
	if !m.DstPort.IsZero() && event.DstPort != 0 {
		res = res && m.DstPort.Match(event.DstPort)
	}

	if m.ExecPath != "" {
		res = res && matchPattern(m.ExecPath, event.ExecPath)
	}
	if m.ParentProcess != "" {
		res = res && matchPattern(m.ParentProcess, event.ParentProcessName)
	}

	if m.FilePath != "" {
		res = res && matchPattern(m.FilePath, event.FilePath)
	}

	if m.FileOp != "" {
		res = res && matchPattern(m.FileOp, event.FileOp)
	}

	return res
}

func (r *Rule) MatchEvent(event core.Event) bool {
	if r.Match != nil { // Single match detection
		return r.Match.MatchEvent(event)
	}

	if len(r.Any) > 0 { // OR logic
		for _, match := range r.Any {
			if match.MatchEvent(event) {
				return true
			}
		}
		return false
	}

	if len(r.All) > 0 { // AND logic
		for _, match := range r.All {
			if !match.MatchEvent(event) {
				return false
			}
		}
		return true
	}

	return false
}
