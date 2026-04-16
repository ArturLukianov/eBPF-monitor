package ruleengine

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
	"go.yaml.in/yaml/v3"
)

type RuleEngine struct {
	rules      []Rule
	alerts     chan core.Alert
	thresholds map[string]*thresholdWindow

	mu sync.Mutex
}

type thresholdWindow struct {
	timestamps []time.Time
	windowSize time.Duration
	threshold  int
}

func (tw *thresholdWindow) AddEvent(timestamp time.Time) int {
	tw.timestamps = append(tw.timestamps, timestamp)

	// Remove old timestamps that are outside the window
	now := timestamp
	for len(tw.timestamps) > 0 && now.Sub(tw.timestamps[0]) > tw.windowSize {
		tw.timestamps = tw.timestamps[1:]
	}

	return len(tw.timestamps)
}

func New(rulesPath string) *RuleEngine {
	engine := &RuleEngine{
		alerts:     make(chan core.Alert, 100),
		thresholds: make(map[string]*thresholdWindow),
	}
	err := engine.LoadRules(rulesPath)
	if err != nil {
		slog.Error("could not load rules", "error", err.Error())
		return nil
	}
	slog.Info("rules loaded", "count", len(engine.rules))

	return engine
}

func (engine *RuleEngine) Alerts() <-chan core.Alert {
	return engine.alerts
}

// Find and load all rules in path and subdirs
func (r *RuleEngine) LoadRules(path string) error {
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		filename := d.Name()
		if strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml") {
			ruleData, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var rule Rule
			err = yaml.Unmarshal(ruleData, &rule)
			if err != nil {
				return err
			}
			slog.Debug("Loaded rule", "rule", rule)
			r.rules = append(r.rules, rule)
		}

		return nil
	})

	return err
}

func buildGroupKey(ruleName string, groupBy []string, event core.Event) string {
	var keys []string
	keys = append(keys, ruleName)
	for _, field := range groupBy {
		switch field {
		case "src_container":
			keys = append(keys, event.SrcContainer.Name)
		case "dst_container":
			if event.DstContainer == nil {
				keys = append(keys, "")
			} else {
				keys = append(keys, event.DstContainer.Name)
			}
		case "src_addr":
			keys = append(keys, event.SrcAddr)
		case "dst_addr":
			keys = append(keys, event.DstAddr)
		case "src_port":
			keys = append(keys, fmt.Sprintf("%d", event.SrcPort))
		case "dst_port":
			keys = append(keys, fmt.Sprintf("%d", event.DstPort))
		default:
			slog.Warn("Unknown group field, ignoring", "field", field)
		}
	}
	return strings.Join(keys, ":")
}

func (r *RuleEngine) handleThreshold(rule Rule, event core.Event) {
	groupKey := buildGroupKey(rule.Name, rule.Detect.GroupBy, event)

	windowSize, err := time.ParseDuration(rule.Detect.Window)
	if err != nil {
		slog.Warn("Invalid window size, setting default 10s", "window", rule.Detect.Window)
		windowSize = 10 * time.Second
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	th, ok := r.thresholds[groupKey]
	if !ok {
		th = &thresholdWindow{
			windowSize: windowSize,
			threshold:  rule.Detect.Count,
		}
		r.thresholds[groupKey] = th
	}

	count := th.AddEvent(event.Timestamp)

	if count > rule.Detect.Count {
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

func (r *RuleEngine) ProcessEvent(event core.Event) {
	for _, rule := range r.rules {
		if !rule.MatchEvent(event) {
			continue
		}

		// Apply detection
		switch rule.Detect.Mode {
		case "threshold":
			r.handleThreshold(rule, event)
		default:
			r.emitAlert(core.Alert{
				Timestamp:   event.Timestamp,
				RuleName:    rule.Name,
				Severity:    rule.Severity,
				Description: rule.Description,

				SrcContainer: event.SrcContainer,
				DstContainer: event.DstContainer,
			})
		}
	}
}

func (r *RuleEngine) ProcessLoop(eventsCh <-chan core.Event) {
	for event := range eventsCh {
		r.ProcessEvent(event)
	}
}

func (r *RuleEngine) emitAlert(alert core.Alert) {
	r.alerts <- alert
}
