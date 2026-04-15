package rule

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type RuleEngine struct {
	rules []Rule
}

func New() *RuleEngine {
	return &RuleEngine{}
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
			r.rules = append(r.rules, rule)
		}

		return nil
	})

	return err
}
