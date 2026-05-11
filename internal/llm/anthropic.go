package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/config"
)

// anthropicClient talks to either the official Anthropic Messages API or any
// compatible proxy (e.g. OpenRouter, LiteLLM, Bedrock-proxies, internal
// gateways) configured via ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN.
//
// Auth resolution (in order):
//  1. spec.APIKeyEnv (if set in config)
//  2. ANTHROPIC_API_KEY     -> sent as "x-api-key"
//  3. ANTHROPIC_AUTH_TOKEN  -> sent as "Authorization: Bearer ..." (proxy mode)
//
// Base URL resolution:
//  1. spec.BaseURL
//  2. ANTHROPIC_BASE_URL
//  3. https://api.anthropic.com
type anthropicClient struct {
	baseURL string
	apiKey  string
	spec    config.ModelSpec
	http    *http.Client

	// useBearer makes the client send "Authorization: Bearer <token>" instead
	// of the native "x-api-key" header. Enabled when ANTHROPIC_AUTH_TOKEN is
	// used (typical for proxies) or when the user explicitly sets
	// APIKeyEnv=ANTHROPIC_AUTH_TOKEN.
	useBearer bool

	// anthropicVersion header; configurable for proxies that pin a version.
	anthropicVersion string
}

func newAnthropicClient(spec config.ModelSpec) (*anthropicClient, error) {
	base := resolveBaseURL(spec.BaseURL, "https://api.anthropic.com", "ANTHROPIC_BASE_URL")

	// Auth resolution.
	var (
		apiKey    string
		usedEnv   string
		useBearer bool
	)
	// 1) explicit env from config.
	if spec.APIKeyEnv != "" {
		apiKey, usedEnv = envFirstNonEmpty(spec.APIKeyEnv)
		if strings.EqualFold(spec.APIKeyEnv, "ANTHROPIC_AUTH_TOKEN") {
			useBearer = true
		}
	}
	// 2) standard ANTHROPIC_API_KEY (native x-api-key).
	if apiKey == "" {
		apiKey, usedEnv = envFirstNonEmpty("ANTHROPIC_API_KEY")
	}
	// 3) ANTHROPIC_AUTH_TOKEN (proxy / Bearer mode).
	if apiKey == "" {
		if v, name := envFirstNonEmpty("ANTHROPIC_AUTH_TOKEN"); v != "" {
			apiKey = v
			usedEnv = name
			useBearer = true
		}
	}
	if apiKey == "" {
		return nil, fmt.Errorf("missing API key for anthropic model %s (tried env: %s)",
			spec.Model, anthropicEnvHint(spec.APIKeyEnv))
	}
	if spec.APIKeyEnv == "" {
		spec.APIKeyEnv = usedEnv
	}

	version := strings.TrimSpace(os.Getenv("ANTHROPIC_VERSION"))
	if version == "" {
		version = "2023-06-01"
	}

	authHeader := "x-api-key"
	if useBearer {
		authHeader = "bearer"
	}
	logEndpointOnce("anthropic", spec.Model, base, "https://api.anthropic.com", spec.APIKeyEnv,
		"auth="+authHeader, "version="+version)

	return &anthropicClient{
		baseURL:          base,
		apiKey:           apiKey,
		spec:             spec,
		http:             defaultHTTP(),
		useBearer:        useBearer,
		anthropicVersion: version,
	}, nil
}

func anthropicEnvHint(specEnv string) string {
	parts := []string{}
	if specEnv != "" {
		parts = append(parts, specEnv)
	}
	parts = append(parts, "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
	return strings.Join(parts, ", ")
}

func (c *anthropicClient) Name() string { return "anthropic/" + c.spec.Model }

type antContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type antMessage struct {
	Role    string            `json:"role"`
	Content []antContentBlock `json:"content"`
}
type antRequest struct {
	Model       string       `json:"model"`
	System      string       `json:"system,omitempty"`
	Messages    []antMessage `json:"messages"`
	MaxTokens   int          `json:"max_tokens"`
	Temperature float64      `json:"temperature"`
}
type antResponse struct {
	Content []antContentBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *anthropicClient) Complete(ctx context.Context, req Request) (Response, error) {
	msgs := make([]antMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			// merged into top-level system below
			continue
		}
		msgs = append(msgs, antMessage{
			Role:    m.Role,
			Content: []antContentBlock{{Type: "text", Text: m.Content}},
		})
	}
	system := req.System
	if req.JSON {
		system += "\n\nIMPORTANT: respond with a single JSON object. No prose, no markdown fences."
		if req.Schema != nil {
			schemaJSON, _ := json.Marshal(req.Schema)
			system += "\nMust conform to schema: " + string(schemaJSON)
		}
	}
	temp := c.spec.Temperature
	if req.TemperatureOverride != nil {
		temp = *req.TemperatureOverride
	}
	body := antRequest{
		Model:       c.spec.Model,
		System:      system,
		Messages:    msgs,
		MaxTokens:   c.spec.MaxTokens,
		Temperature: temp,
	}
	buf, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(buf))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", c.anthropicVersion)
	if c.useBearer {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	} else {
		httpReq.Header.Set("x-api-key", c.apiKey)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic http: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("anthropic http %d: %s", resp.StatusCode, string(raw))
	}
	var out antResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("anthropic decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return Response{}, errors.New("anthropic: " + out.Error.Message)
	}
	var text strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return Response{
		Text:       text.String(),
		TokensIn:   out.Usage.InputTokens,
		TokensOut:  out.Usage.OutputTokens,
		Provider:   "anthropic",
		Model:      c.spec.Model,
		FinishedAt: time.Now(),
	}, nil
}
