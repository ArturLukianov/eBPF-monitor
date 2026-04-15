package ruleengine

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type PortExpr struct {
	Ports  []uint16
	Ranges [][2]uint16
	Negate bool

	Wildcard bool // If true, match all ports
}

func ParsePortExpr(s string) (PortExpr, error) {
	raw := strings.TrimSpace(s)

	if raw == "*" || raw == "" {
		return PortExpr{Wildcard: true}, nil
	}

	var expr PortExpr

	if strings.HasPrefix(raw, "!") {
		expr.Negate = true
		raw = raw[1:]
	}

	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}

	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"'")
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") { // Range
			rangeParts := strings.SplitN(part, "-", 2)
			rangeStart, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 16)
			if err != nil {
				return expr, fmt.Errorf("invalid port range start: %w", err)
			}
			rangeEnd, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 16)
			if err != nil {
				return expr, fmt.Errorf("invalid port range end: %w", err)
			}
			expr.Ranges = append(expr.Ranges, [2]uint16{uint16(rangeStart), uint16(rangeEnd)})
		} else {
			port, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				return expr, fmt.Errorf("invalid port: %w", err)
			}
			expr.Ports = append(expr.Ports, uint16(port))
		}
	}

	return expr, nil
}

func (p *PortExpr) Match(port uint16) bool {
	matched := false

	for _, p := range p.Ports {
		if p == port {
			matched = true
			break
		}
	}

	if !matched {
		for _, r := range p.Ranges {
			if port >= r[0] && port <= r[1] {
				matched = true
				break
			}
		}
	}

	if p.Negate {
		matched = !matched
	}

	return matched
}

func (p *PortExpr) IsZero() bool {
	return !p.Wildcard && !p.Negate && len(p.Ports) == 0 && len(p.Ranges) == 0
}

// dst_port: 22
// dst_port: "!5432"
// dst_port: [22, 80, "8000-9000"]
// currently not supports ["!5432"]
func (p *PortExpr) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// Single value: 22, "!5432", "1-1024"
		parsed, err := ParsePortExpr(value.Value)
		if err != nil {
			return err
		}
		*p = parsed
		return nil

	case yaml.SequenceNode:
		// List: [22, 80, "8000-9000"]
		for _, item := range value.Content {
			parsed, err := ParsePortExpr(item.Value)
			if err != nil {
				return err
			}
			p.Ports = append(p.Ports, parsed.Ports...)
			p.Ranges = append(p.Ranges, parsed.Ranges...)
		}
		return nil

	default:
		return fmt.Errorf("unexpected YAML node kind %d for port expression", value.Kind)
	}
}
