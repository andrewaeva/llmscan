package llm

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
)

func TestAnthropicAuthResolution(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		specEnv    string
		specURL    string
		wantBase   string
		wantBearer bool
		wantErr    bool
	}{
		{
			name:     "native ANTHROPIC_API_KEY",
			env:      map[string]string{"ANTHROPIC_API_KEY": "sk-ant-test"},
			wantBase: "https://api.anthropic.com",
		},
		{
			name:       "proxy: ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN",
			env:        map[string]string{"ANTHROPIC_BASE_URL": "https://proxy.example.com/v1", "ANTHROPIC_AUTH_TOKEN": "bearer-xyz"},
			wantBase:   "https://proxy.example.com/v1",
			wantBearer: true,
		},
		{
			name:       "AUTH_TOKEN preferred when explicitly named",
			env:        map[string]string{"ANTHROPIC_API_KEY": "should-ignore", "ANTHROPIC_AUTH_TOKEN": "bearer-xyz"},
			specEnv:    "ANTHROPIC_AUTH_TOKEN",
			wantBase:   "https://api.anthropic.com",
			wantBearer: true,
		},
		{
			name:     "spec base URL wins over env",
			env:      map[string]string{"ANTHROPIC_BASE_URL": "https://env.example.com", "ANTHROPIC_API_KEY": "k"},
			specURL:  "https://spec.example.com/v1/",
			wantBase: "https://spec.example.com/v1",
		},
		{
			name:    "no key available",
			env:     map[string]string{},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_VERSION"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			spec := config.ModelSpec{Provider: "anthropic", Model: "claude-3-5-sonnet", APIKeyEnv: tc.specEnv, BaseURL: tc.specURL}
			c, err := newAnthropicClient(spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got client %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.baseURL != tc.wantBase {
				t.Errorf("baseURL = %q, want %q", c.baseURL, tc.wantBase)
			}
			if c.useBearer != tc.wantBearer {
				t.Errorf("useBearer = %v, want %v", c.useBearer, tc.wantBearer)
			}
			if c.anthropicVersion == "" {
				t.Errorf("expected default anthropic-version, got empty")
			}
		})
	}
}

func TestAnthropicVersionOverride(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	t.Setenv("ANTHROPIC_VERSION", "2024-10-22")
	c, err := newAnthropicClient(config.ModelSpec{Provider: "anthropic", Model: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.anthropicVersion != "2024-10-22" {
		t.Errorf("version = %q, want 2024-10-22", c.anthropicVersion)
	}
}

func TestOpenAIBaseURLEnv(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("OPENAI_BASE_URL", "https://oai-proxy.example.com/v1")
	c, err := newOpenAIClient(config.ModelSpec{Provider: "openai", Model: "gpt-4o-mini"}, "openai")
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://oai-proxy.example.com/v1" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}
