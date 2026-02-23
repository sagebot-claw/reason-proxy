package main

import (
	"os"
	"path/filepath"
	"testing"
)

func testConfig() *Config {
	cfg := &Config{
		Policy:   "lax",
		Allow:    []string{"api.openai.com", "api.anthropic.com"},
		Deny:     []string{"malicious.example.com"},
		Grey:     []string{"api.github.com"},
		Keywords: []string{"password", "secret_key", "credential"},
	}
	cfg.buildSets()
	return cfg
}

// --- Classify ---

func TestClassify_AllowListed(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("api.openai.com"); got != HostAllow {
		t.Errorf("expected HostAllow, got %v", got)
	}
}

func TestClassify_AllowListedWithPort(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("api.openai.com:443"); got != HostAllow {
		t.Errorf("expected HostAllow, got %v", got)
	}
}

func TestClassify_DenyListed(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("malicious.example.com"); got != HostDeny {
		t.Errorf("expected HostDeny, got %v", got)
	}
}

func TestClassify_DenyListedWithPort(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("malicious.example.com:8080"); got != HostDeny {
		t.Errorf("expected HostDeny, got %v", got)
	}
}

func TestClassify_GreyListed(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("api.github.com"); got != HostGrey {
		t.Errorf("expected HostGrey, got %v", got)
	}
}

func TestClassify_Unlisted(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("unknown.example.com"); got != HostUnlisted {
		t.Errorf("expected HostUnlisted, got %v", got)
	}
}

func TestClassify_CaseInsensitive(t *testing.T) {
	cfg := testConfig()
	if got := cfg.Classify("API.OpenAI.COM"); got != HostAllow {
		t.Errorf("expected HostAllow for uppercase host, got %v", got)
	}
}

// --- Decide (full matrix) ---

func TestDecide_Matrix(t *testing.T) {
	tests := []struct {
		policy string
		class  HostClass
		want   Action
	}{
		// open mode
		{"open", HostAllow, ActionAllow},
		{"open", HostDeny, ActionDeny},
		{"open", HostGrey, ActionEvaluate},
		{"open", HostUnlisted, ActionAllow},
		// lax mode
		{"lax", HostAllow, ActionAllow},
		{"lax", HostDeny, ActionDeny},
		{"lax", HostGrey, ActionEvaluate},
		{"lax", HostUnlisted, ActionEvaluate},
		// strict mode
		{"strict", HostAllow, ActionAllow},
		{"strict", HostDeny, ActionDeny},
		{"strict", HostGrey, ActionDeny},
		{"strict", HostUnlisted, ActionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.policy+"_"+tt.class.String(), func(t *testing.T) {
			cfg := &Config{Policy: tt.policy}
			if got := cfg.Decide(tt.class); got != tt.want {
				t.Errorf("Decide(%v) in %s mode = %v, want %v",
					tt.class, tt.policy, got, tt.want)
			}
		})
	}
}

// --- EvaluateResponse ---

func TestEvaluateResponse_Match(t *testing.T) {
	cfg := testConfig()
	passed, kw := cfg.EvaluateResponse([]byte(`{"token": "secret_key_abc123"}`))
	if passed {
		t.Error("expected evaluation to fail")
	}
	if kw != "secret_key" {
		t.Errorf("expected matched keyword 'secret_key', got %q", kw)
	}
}

func TestEvaluateResponse_CaseInsensitive(t *testing.T) {
	cfg := testConfig()
	passed, kw := cfg.EvaluateResponse([]byte(`Your PASSWORD is wrong`))
	if passed {
		t.Error("expected evaluation to fail for case-insensitive match")
	}
	if kw != "password" {
		t.Errorf("expected matched keyword 'password', got %q", kw)
	}
}

func TestEvaluateResponse_NoMatch(t *testing.T) {
	cfg := testConfig()
	passed, kw := cfg.EvaluateResponse([]byte(`{"status": "ok", "data": [1,2,3]}`))
	if !passed {
		t.Errorf("expected evaluation to pass, but matched %q", kw)
	}
}

func TestEvaluateResponse_EmptyBody(t *testing.T) {
	cfg := testConfig()
	passed, _ := cfg.EvaluateResponse([]byte{})
	if !passed {
		t.Error("expected evaluation to pass on empty body")
	}
}

func TestEvaluateResponse_NoKeywords(t *testing.T) {
	cfg := &Config{Keywords: nil}
	cfg.buildSets()
	passed, _ := cfg.EvaluateResponse([]byte("password secret_key credential"))
	if !passed {
		t.Error("expected evaluation to pass when no keywords configured")
	}
}

// --- LoadConfig ---

func TestLoadConfig_Valid(t *testing.T) {
	content := `
policy: strict
allow:
  - api.openai.com
deny:
  - evil.com
grey:
  - api.github.com
keywords:
  - password
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.Policy != "strict" {
		t.Errorf("expected policy 'strict', got %q", cfg.Policy)
	}
	if len(cfg.Allow) != 1 || cfg.Allow[0] != "api.openai.com" {
		t.Errorf("unexpected allow list: %v", cfg.Allow)
	}
	if len(cfg.Keywords) != 1 || cfg.Keywords[0] != "password" {
		t.Errorf("unexpected keywords: %v", cfg.Keywords)
	}
	// Verify sets are built
	if cfg.Classify("api.openai.com") != HostAllow {
		t.Error("expected classify to work after LoadConfig")
	}
}

func TestLoadConfig_InvalidPolicy(t *testing.T) {
	content := `policy: yolo`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid policy mode")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Policy != "open" {
		t.Errorf("expected default policy 'open', got %q", cfg.Policy)
	}
	// Unlisted hosts should be allowed in open mode
	if cfg.Decide(cfg.Classify("anything.com")) != ActionAllow {
		t.Error("expected unlisted host to be allowed in open mode")
	}
}
