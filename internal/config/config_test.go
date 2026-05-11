package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBaseline(t *testing.T) {
	c := Default()
	if c.DefaultModel.Provider != "anthropic" {
		t.Errorf("default provider = %q", c.DefaultModel.Provider)
	}
	if c.DefaultModel.Temperature != 0.1 {
		t.Errorf("default temp = %v", c.DefaultModel.Temperature)
	}
	if c.DefaultModel.MaxTokens != 4096 {
		t.Errorf("default max tokens = %v", c.DefaultModel.MaxTokens)
	}
	if !c.Agents["orchestrator"].Enabled {
		t.Error("orchestrator should be enabled by default")
	}
	if !c.Agents["verifier"].Enabled {
		t.Error("verifier should be enabled by default")
	}
	if !c.DropFalsePositives {
		t.Error("DropFalsePositives default should be true")
	}
	if c.VerifierConfidenceThreshold != ConfLow {
		t.Errorf("verifier threshold = %q", c.VerifierConfidenceThreshold)
	}
	if c.Scan.ChunkLines == 0 || c.Scan.MaxFileBytes == 0 {
		t.Errorf("scan defaults missing: %+v", c.Scan)
	}
	if !c.Precision.PreFilterWatchlist || !c.Precision.SecretsPreFilter {
		t.Error("precision defaults should enable watchlist+secrets prefilter")
	}
	if c.Precision.JSONRetries != 2 {
		t.Errorf("json retries = %d", c.Precision.JSONRetries)
	}
	if !c.Cache.Enabled || c.Cache.Path == "" {
		t.Errorf("cache defaults: %+v", c.Cache)
	}
	if c.Deep.Enabled {
		t.Error("deep should be disabled by default")
	}
	if c.Deep.MinSeverity != "high" {
		t.Errorf("deep min severity = %q", c.Deep.MinSeverity)
	}
	if c.Deep.MaxFileBytes == 0 {
		t.Errorf("deep MaxFileBytes default missing")
	}
}

func TestLoadEmptyPathReturnsDefault(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c.DefaultModel.Provider != "anthropic" {
		t.Errorf("got=%+v", c.DefaultModel)
	}
}

func TestLoadMissingFileError(t *testing.T) {
	_, err := Load("/nonexistent-path-12345/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	d := t.TempDir()
	bad := filepath.Join(d, "bad.yaml")
	if err := os.WriteFile(bad, []byte("invalid: [unterminated"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(bad)
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestLoadMergesYAMLOnTopOfDefaults(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "cfg.yaml")
	yaml := `default_model:
  provider: openai
  model: gpt-4o-mini
  temperature: 0.3
project_context: "test project"
agents:
  injection:
    enabled: false
  custom-skill:
    enabled: true
deep:
  enabled: true
  min_severity: critical
`
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultModel.Provider != "openai" || c.DefaultModel.Model != "gpt-4o-mini" {
		t.Errorf("default_model not loaded: %+v", c.DefaultModel)
	}
	if c.ProjectContext != "test project" {
		t.Errorf("ProjectContext=%q", c.ProjectContext)
	}
	if c.Agents["injection"].Enabled {
		t.Error("injection should now be disabled")
	}
	if !c.Agents["custom-skill"].Enabled {
		t.Error("custom-skill agent should be enabled")
	}
	if !c.Deep.Enabled || c.Deep.MinSeverity != "critical" {
		t.Errorf("deep overrides not applied: %+v", c.Deep)
	}
	// Defaults still propagate to untouched fields.
	if c.Scan.ChunkLines == 0 {
		t.Error("scan defaults overwritten")
	}
}

func TestResolveModelFallsBackToDefault(t *testing.T) {
	c := Default()
	m := c.ResolveModel("injection")
	if m.Provider != "anthropic" || m.Model == "" {
		t.Errorf("expected default model, got %+v", m)
	}
	if m.APIKeyEnv != "ANTHROPIC_API_KEY" {
		t.Errorf("APIKeyEnv=%q", m.APIKeyEnv)
	}
	if m.Temperature == 0 || m.MaxTokens == 0 {
		t.Errorf("defaults not applied: %+v", m)
	}
}

func TestResolveModelAgentOverride(t *testing.T) {
	c := Default()
	c.Agents["injection"] = AgentConfig{
		Enabled: true,
		Model: ModelSpec{
			Provider:    "openai",
			Model:       "gpt-4o",
			Temperature: 0.5,
			MaxTokens:   2000,
			BaseURL:     "https://example/v1",
			APIKeyEnv:   "MY_KEY",
		},
	}
	m := c.ResolveModel("injection")
	if m.Provider != "openai" || m.Model != "gpt-4o" {
		t.Errorf("override not honored: %+v", m)
	}
	if m.Temperature != 0.5 || m.MaxTokens != 2000 {
		t.Errorf("temperature/maxtokens: %+v", m)
	}
	if m.BaseURL != "https://example/v1" || m.APIKeyEnv != "MY_KEY" {
		t.Errorf("base/key: %+v", m)
	}
}

func TestResolveModelPartialOverrideFallback(t *testing.T) {
	c := Default()
	// Only override Model name; other fields fall back to default.
	c.Agents["injection"] = AgentConfig{Model: ModelSpec{Model: "haiku-x"}}
	m := c.ResolveModel("injection")
	if m.Model != "haiku-x" {
		t.Errorf("model=%q", m.Model)
	}
	if m.Provider != "anthropic" {
		t.Errorf("provider should fall back to default, got %q", m.Provider)
	}
	if m.Temperature == 0 {
		t.Error("temperature default not applied")
	}
}

func TestResolveModelEmptyProviderDefaultsToOpenAI(t *testing.T) {
	c := Default()
	c.DefaultModel = ModelSpec{Provider: "openai", Model: "x"} // no APIKeyEnv
	m := c.ResolveModel("anything")
	if m.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("expected default OPENAI_API_KEY, got %q", m.APIKeyEnv)
	}
}

func TestIsAgentEnabledDefault(t *testing.T) {
	c := Default()
	if !c.IsAgentEnabled("unknown-agent") {
		t.Error("unknown agents default to enabled")
	}
	if !c.IsAgentEnabled("orchestrator") {
		t.Error("orchestrator should be enabled")
	}
	c.Agents["xyz"] = AgentConfig{Enabled: false}
	if c.IsAgentEnabled("xyz") {
		t.Error("xyz should be disabled")
	}
}

func TestConfidenceConstants(t *testing.T) {
	// Sanity check string values are stable.
	if string(ConfHigh) != "high" || string(ConfMedium) != "medium" || string(ConfLow) != "low" {
		t.Errorf("confidence constants drifted: %q %q %q", ConfHigh, ConfMedium, ConfLow)
	}
}
