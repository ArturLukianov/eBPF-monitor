package rule

type PortExpr struct {
	Ports  []uint16
	Ranges [][2]uint16
	Negate bool
}

type MatchBlock struct {
	SrcProcess   string `yaml:"src_process"`
	DstProcess   string `yaml:"dst_process"`
	SrcContainer string `yaml:"src_container"`
	DstContainer string `yaml:"dst_container"`
	SrcPort      string `yaml:"src_port"`
	DstPort      string `yaml:"dst_port"`
	Not          *MatchBlock
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
}
