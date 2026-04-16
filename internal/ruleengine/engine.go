package ruleengine

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ArturLukianov/eBPF-monitor/internal/core"
	"go.yaml.in/yaml/v3"
)

type RuleEngine struct {
	rules  []Rule
	alerts chan core.Alert

	mu sync.Mutex
}

func New(rulesPath string) *RuleEngine {
	engine := &RuleEngine{
		alerts: make(chan core.Alert, 100),
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

func (r *RuleEngine) ProcessEvent(event core.Event) {
	slog.Debug("Processing event")
	for _, rule := range r.rules {
		if !rule.MatchEvent(event) {
			continue
		}

		// Apply detection
		switch rule.Detect.Mode {
		default:
			r.emitAlert(core.Alert{
				Timestamp:   event.Timestamp,
				RuleName:    rule.Name,
				Severity:    rule.Severity,
				Description: rule.Description,

				SrcContainer: &event.SrcContainer,
				DstContainer: &event.DstContainer,
			})
		}
	}
}

func (r *RuleEngine) ProcessLoop(eventsCh <-chan core.Event) {
	for event := range eventsCh {
		slog.Debug("Receieved event")
		r.ProcessEvent(event)
	}
}

func (r *RuleEngine) emitAlert(alert core.Alert) {
	r.alerts <- alert
}
