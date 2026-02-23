package policy

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// HostClass represents the classification of a host.
type HostClass int

const (
	HostAllow    HostClass = iota
	HostDeny
	HostGrey
	HostUnlisted
)

func (h HostClass) String() string {
	switch h {
	case HostAllow:
		return "allow"
	case HostDeny:
		return "deny"
	case HostGrey:
		return "grey"
	case HostUnlisted:
		return "unlisted"
	default:
		return "unknown"
	}
}

// Action represents the proxy's decision for a request.
type Action int

const (
	ActionAllow    Action = iota
	ActionDeny
	ActionEvaluate
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionEvaluate:
		return "evaluate"
	default:
		return "unknown"
	}
}

// Config holds the policy configuration loaded from YAML.
type Config struct {
	Policy   string   `yaml:"policy"`
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
	Grey     []string `yaml:"grey"`
	Keywords []string `yaml:"keywords"`

	// Pre-built lookup maps (not serialized).
	allowSet map[string]bool
	denySet  map[string]bool
	greySet  map[string]bool
}

// LoadConfig reads and parses a YAML policy file. Returns an error if the
// file cannot be read or if the policy mode is invalid.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	switch cfg.Policy {
	case "open", "lax", "strict":
		// valid
	default:
		return nil, fmt.Errorf("invalid policy mode: %q (must be open, lax, or strict)", cfg.Policy)
	}

	cfg.buildSets()
	return &cfg, nil
}

// DefaultConfig returns an open-policy config with empty lists. This is used
// when no config file is present, preserving backwards compatibility.
func DefaultConfig() *Config {
	cfg := &Config{Policy: "open"}
	cfg.buildSets()
	return cfg
}

func (c *Config) buildSets() {
	c.allowSet = make(map[string]bool, len(c.Allow))
	for _, h := range c.Allow {
		c.allowSet[strings.ToLower(h)] = true
	}
	c.denySet = make(map[string]bool, len(c.Deny))
	for _, h := range c.Deny {
		c.denySet[strings.ToLower(h)] = true
	}
	c.greySet = make(map[string]bool, len(c.Grey))
	for _, h := range c.Grey {
		c.greySet[strings.ToLower(h)] = true
	}
}

// stripPort returns the hostname portion of a host string, removing any port.
func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port present (or some other parse issue) — use as-is.
		return host
	}
	return h
}

// Classify determines which list a host belongs to.
func (c *Config) Classify(host string) HostClass {
	h := strings.ToLower(stripPort(host))
	if c.denySet[h] {
		return HostDeny
	}
	if c.allowSet[h] {
		return HostAllow
	}
	if c.greySet[h] {
		return HostGrey
	}
	return HostUnlisted
}

// Decide applies the policy matrix to a host classification and returns the
// resulting action.
func (c *Config) Decide(class HostClass) Action {
	switch class {
	case HostAllow:
		return ActionAllow
	case HostDeny:
		return ActionDeny
	case HostGrey:
		if c.Policy == "strict" {
			return ActionDeny
		}
		return ActionEvaluate
	case HostUnlisted:
		switch c.Policy {
		case "open":
			return ActionAllow
		case "lax":
			return ActionEvaluate
		case "strict":
			return ActionDeny
		}
	}
	return ActionDeny
}

// EvaluateResponse performs a case-insensitive keyword scan on the response
// body. It returns (true, "") if no keywords match, or (false, keyword) with
// the first matched keyword.
func (c *Config) EvaluateResponse(body []byte) (bool, string) {
	lower := bytes.ToLower(body)
	for _, kw := range c.Keywords {
		if bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			return false, kw
		}
	}
	return true, ""
}
