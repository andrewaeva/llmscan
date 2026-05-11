// Package llm provides a thin, provider-agnostic LLM client used by all agents.
//
// Supported providers:
//   - "openai":    OpenAI-compatible Chat Completions (also for any OpenAI-compatible endpoint).
//   - "opencode":  OpenAI-compatible OpenCode endpoint.
//   - "anthropic": Anthropic Messages API (or any compatible proxy via
//     ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN).
//
// The package intentionally avoids external SDKs to keep dependencies minimal.
package llm

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andrewaeva/llmscan/internal/config"
)

// endpointLogOnce ensures each (provider|baseURL|model|auth) tuple is logged only once per process.
var endpointLogOnce sync.Map

// logEndpointOnce prints one informational line per unique LLM endpoint configuration.
// `extra` lets callers append fields like "auth=bearer (proxy)" or "auth=x-api-key".
func logEndpointOnce(provider, model, baseURL, defaultBaseURL, authEnv string, extra ...string) {
	key := provider + "|" + baseURL + "|" + model + "|" + authEnv
	if _, loaded := endpointLogOnce.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	mode := "direct"
	if baseURL != "" && baseURL != defaultBaseURL {
		mode = "proxy"
	}
	fields := make([]string, 0, 5+len(extra))
	fields = append(fields,
		"provider="+provider,
		"model="+model,
		"base_url="+baseURL,
		"mode="+mode,
		"auth_env="+authEnv,
	)
	fields = append(fields, extra...)
	log.Printf("[llm] %s", strings.Join(fields, " ")) //nolint:gosec // fields are static config keys, not user input
}

// Message is a single chat message.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Request describes a completion request.
type Request struct {
	System   string
	Messages []Message
	// JSON indicates JSON-only response is expected (provider-specific hints applied).
	JSON bool
	// Schema, if non-nil, is sent as a strict JSON-schema (OpenAI response_format=json_schema).
	// For providers without native support, it is appended to the system prompt.
	Schema map[string]any
	// SchemaName labels the schema (required by OpenAI strict mode).
	SchemaName string
	// TemperatureOverride lets callers bump temperature for voting/self-consistency.
	TemperatureOverride *float64
}

// Response carries the textual completion and basic usage info.
type Response struct {
	Text       string
	TokensIn   int
	TokensOut  int
	Provider   string
	Model      string
	FinishedAt time.Time
}

// Client is the high-level LLM interface used by agents.
type Client interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// envFirstNonEmpty returns the first non-empty value among the given env var names.
// The returned bool indicates which name succeeded (empty if none).
func envFirstNonEmpty(names ...string) (value string, name string) {
	for _, n := range names {
		if n == "" {
			continue
		}
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v, n
		}
	}
	return "", ""
}

// resolveBaseURL picks the first non-empty value from spec.BaseURL, listed env vars, then fallback.
func resolveBaseURL(specURL string, fallback string, envNames ...string) string {
	if specURL != "" {
		return strings.TrimRight(specURL, "/")
	}
	if v, _ := envFirstNonEmpty(envNames...); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(fallback, "/")
}

// New returns a client for the given model spec.
func New(spec config.ModelSpec) (Client, error) {
	switch strings.ToLower(spec.Provider) {
	case "", "openai":
		return newOpenAIClient(spec, "openai")
	case "opencode":
		return newOpenAIClient(spec, "opencode")
	case "anthropic":
		return newAnthropicClient(spec)
	default:
		return nil, fmt.Errorf("unknown provider %q", spec.Provider)
	}
}

func defaultHTTP() *http.Client {
	return &http.Client{Timeout: 120 * time.Second}
}
