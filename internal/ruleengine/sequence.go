package ruleengine

import (
	"log/slog"
	"time"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
)

type SequenceStep = MatchBlock

// This is what appears in YAML
type SequenceConfig struct {
	Window  string         `yaml:"window"`
	GroupBy []string       `yaml:"group_by"` // Defaults to src_container
	Steps   []SequenceStep `yaml:"steps"`
}

type sequenceTracker struct {
	currentStep int
	stepTimes   []time.Time
	window      time.Duration
}

type sequenceState struct {
	trackers map[string]*sequenceTracker
}

func (tracker *sequenceTracker) advanceStep(stepIndex int, timestamp time.Time) {
	if tracker.currentStep != stepIndex {
		return
	}

	if tracker.currentStep == 0 {
		tracker.stepTimes = []time.Time{timestamp}
		tracker.currentStep++
		return
	}

	// Check is within window
	if timestamp.Sub(tracker.stepTimes[0]) > tracker.window {
		tracker.currentStep = 0
		tracker.stepTimes = nil
		return
	}

	tracker.stepTimes = append(tracker.stepTimes, timestamp)
	tracker.currentStep++
}

func (r *RuleEngine) handleSequence(rule Rule, event core.Event) {
	seq := rule.Sequence
	if seq == nil {
		return
	}

	groupBy := seq.GroupBy
	if len(groupBy) == 0 {
		groupBy = []string{"src_container"}
	}

	key := buildGroupKey(rule.Name, groupBy, event)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if event matches any step

	for stepIdx, step := range seq.Steps {
		if !step.MatchEvent(event) {
			continue
		}

		// Find tracker (or create new)
		tracker, exists := r.sequences.trackers[key]

		if !exists {
			window, err := time.ParseDuration(seq.Window)
			if err != nil {
				slog.Warn("invalid sequence windows, defaulting to 5s", "window", window, "error", err)
				window = 5 * time.Second
			}
			tracker = &sequenceTracker{
				currentStep: stepIdx,
				stepTimes:   []time.Time{event.Timestamp},
				window:      window,
			}
			r.sequences.trackers[key] = tracker
		}

		// Try to advance to next step
		tracker.advanceStep(stepIdx, event.Timestamp)

		// If sequence finished, emit alert
		if tracker.currentStep >= len(seq.Steps) {
			r.emitAlert(core.Alert{
				Timestamp:    event.Timestamp,
				RuleName:     rule.Name,
				Severity:     rule.Severity,
				Description:  rule.Description,
				SrcContainer: event.SrcContainer,
				DstContainer: event.DstContainer,
			})
		}
	}
}

// TODO: add cleanup for expired trackers
