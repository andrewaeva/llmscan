package rag

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
)

// EmbedderSpec describes how to build an embedder.
type EmbedderSpec struct {
	Provider  string `yaml:"provider"`           // openai | opencode | voyage
	Model     string `yaml:"model"`              // e.g. text-embedding-3-small
	BaseURL   string `yaml:"base_url,omitempty"` // override endpoint
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
}

// NewEmbedder constructs the right embedder. Returns nil if Provider is empty
// (callers treat nil as "RAG disabled / keyword-only").
//
//nolint:gocyclo // provider dispatch over many backends
func NewEmbedder(spec EmbedderSpec) (Embedder, error) {
	if spec.Provider == "" {
		return nil, nil
	}
	apiKey := os.Getenv(spec.APIKeyEnv)
	httpClient := &http.Client{Timeout: 120 * time.Second}
	switch strings.ToLower(spec.Provider) {
	case "openai":
		base := spec.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		if spec.APIKeyEnv == "" {
			spec.APIKeyEnv = "OPENAI_API_KEY"
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing %s for openai embedder", spec.APIKeyEnv)
		}
		if spec.Model == "" {
			spec.Model = "text-embedding-3-small"
		}
		return &openAIEmbedder{base: base, key: apiKey, model: spec.Model, http: httpClient}, nil
	case "opencode":
		// opencode.ai exposes an OpenAI-compatible API; reuse the OpenAI client with a different base URL.
		base := spec.BaseURL
		if base == "" {
			base = "https://api.opencode.ai/v1"
		}
		if spec.APIKeyEnv == "" {
			spec.APIKeyEnv = "OPENCODE_API_KEY"
			apiKey = os.Getenv("OPENCODE_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing %s for opencode embedder", spec.APIKeyEnv)
		}
		if spec.Model == "" {
			spec.Model = "opencode-embed-1"
		}
		return &openAIEmbedder{base: base, key: apiKey, model: spec.Model, http: httpClient, label: "opencode"}, nil
	case "voyage":
		if spec.APIKeyEnv == "" {
			spec.APIKeyEnv = "VOYAGE_API_KEY"
			apiKey = os.Getenv("VOYAGE_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing %s for voyage embedder", spec.APIKeyEnv)
		}
		if spec.Model == "" {
			spec.Model = "voyage-code-3"
		}
		base := spec.BaseURL
		if base == "" {
			base = "https://api.voyageai.com/v1"
		}
		return &voyageEmbedder{base: base, key: apiKey, model: spec.Model, http: httpClient}, nil
	}
	return nil, fmt.Errorf("unknown embedder provider %q", spec.Provider)
}

// ---------- OpenAI / opencode (shared shape) ----------

type openAIEmbedder struct {
	base, key, model, label string
	http                    *http.Client
}

type oaEmbReq struct {
	Input []string `json:"input"`
	Model string   `json:"model"`
}
type oaEmbResp struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (e *openAIEmbedder) Name() string {
	if e.label == "" {
		return "openai:" + e.model
	}
	return e.label + ":" + e.model
}

func (e *openAIEmbedder) Dim() int { return 0 }

func (e *openAIEmbedder) Embed(ctx context.Context, batch []string) ([][]float32, error) {
	buf, _ := json.Marshal(oaEmbReq{Input: batch, Model: e.model})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/embeddings", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.key)
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s embeddings http %d: %s", e.Name(), resp.StatusCode, string(raw))
	}
	var out oaEmbResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return nil, errors.New(out.Error.Message)
	}
	res := make([][]float32, len(out.Data))
	for i, d := range out.Data {
		res[i] = d.Embedding
	}
	return res, nil
}

// ---------- Voyage ----------

type voyageEmbedder struct {
	base, key, model string
	http             *http.Client
}

func (e *voyageEmbedder) Name() string { return "voyage:" + e.model }
func (e *voyageEmbedder) Dim() int     { return 0 }

type vyReq struct {
	Input []string `json:"input"`
	Model string   `json:"model"`
}
type vyResp struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (e *voyageEmbedder) Embed(ctx context.Context, batch []string) ([][]float32, error) {
	buf, _ := json.Marshal(vyReq{Input: batch, Model: e.model})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/embeddings", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.key)
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("voyage embeddings http %d: %s", resp.StatusCode, string(raw))
	}
	var out vyResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	res := make([][]float32, len(out.Data))
	for i, d := range out.Data {
		res[i] = d.Embedding
	}
	return res, nil
}
