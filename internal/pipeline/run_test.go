package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/types"
)

// fakeOpenAIServer returns a single httptest server that responds to /chat/completions
// with a JSON-coded answer derived from the system prompt. This lets one server
// serve all agents (orchestrator/scanner/verifier/fp_filter) by routing on the
// system prompt content.
func fakeOpenAIServer(t *testing.T, counter *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if counter != nil {
			atomic.AddInt64(counter, 1)
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		var system, user string
		for _, m := range req.Messages {
			if m.Role == "system" {
				system = m.Content
			}
			if m.Role == "user" {
				user = m.Content
			}
		}
		_ = user
		var reply string
		switch {
		case strings.Contains(system, "Orchestrator agent"):
			reply = `{"reasoning":"plan","priority":[],"focus":["injection"]}`
		case strings.Contains(system, "Verifier agent"):
			reply = `{"verdict":"true_positive","comment":"confirmed","severity":"high","confidence":"high"}`
		case strings.Contains(system, "False-Positive Filter"):
			reply = `{"kept":["dummy"],"dropped":[]}`
		case strings.Contains(system, "Context Filter"):
			reply = `{"keep":[],"reason":"none"}`
		case strings.Contains(system, "injection security agent") || strings.Contains(system, "secrets security agent"):
			// Return one fake finding for each scanner so we exercise the verifier + fp_filter chain.
			reply = `{"findings":[{"rule_id":"r-test","title":"fake issue","severity":"high","confidence":"medium","start_line":1,"end_line":1,"code_sample":"x"}]}`
		default:
			// Generic / other scanners: empty findings.
			reply = `{"findings":[]}`
		}
		respBody := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": reply}},
			},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 5},
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// configForServer wires every agent to a fake OpenAI server.
func configForServer(t *testing.T, srvURL string) config.Config {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", srvURL)
	cfg := config.Default()
	// Switch every default to openai so we don't need ANTHROPIC env.
	cfg.DefaultModel = config.ModelSpec{
		Provider: "openai", Model: "gpt-test",
		Temperature: 0.0, MaxTokens: 128, APIKeyEnv: "OPENAI_API_KEY",
	}
	// Disable optional features that need extra setup.
	cfg.Cache.Enabled = false
	cfg.RAG.Enabled = false
	cfg.Precision.Taint = false
	cfg.Precision.Reachability = false
	cfg.Precision.PreFilterWatchlist = false
	cfg.Precision.SecretsPreFilter = false
	cfg.Precision.VoteN = 0
	cfg.Deep.Enabled = false
	cfg.DropFalsePositives = true
	cfg.Scan.MaxFileBytes = 1 << 20
	cfg.Scan.Concurrency = 2
	cfg.Scan.AgentParallel = 2
	// Restrict to a tiny set of agents to keep the test deterministic and fast.
	for name := range cfg.Agents {
		ac := cfg.Agents[name]
		ac.Enabled = false
		cfg.Agents[name] = ac
	}
	for _, name := range []string{"orchestrator", "injection", "secrets", "verifier", "fp_filter"} {
		cfg.Agents[name] = config.AgentConfig{Enabled: true}
	}
	return cfg
}

func writeRepoFixture(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	mustWrite(t, filepath.Join(d, "vuln.go"),
		"package vuln\nimport \"database/sql\"\nfunc Q(db *sql.DB, name string) {\n\tdb.Exec(\"SELECT * FROM x WHERE n='\"+name+\"'\")\n}\n")
	mustWrite(t, filepath.Join(d, "creds.py"),
		"AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n")
	return d
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEngineRunIntegration(t *testing.T) {
	var calls int64
	srv := fakeOpenAIServer(t, &calls)
	cfg := configForServer(t, srv.URL)
	target := writeRepoFixture(t)
	e := New(cfg)
	rep, err := e.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Target != target {
		t.Errorf("target=%q", rep.Target)
	}
	if rep.FilesScanned == 0 {
		t.Error("expected files scanned > 0")
	}
	// Plan should be populated by orchestrator response.
	if rep.Plan.Reasoning == "" && len(rep.Plan.Priority) == 0 && len(rep.Plan.Focus) == 0 {
		t.Errorf("plan unfilled: %+v", rep.Plan)
	}
	if calls == 0 {
		t.Error("expected the fake LLM to be hit")
	}
	// At least one finding should survive the verifier (which says true_positive).
	// And stats should reflect the pipeline counts.
	if rep.Stats.Raw == 0 {
		t.Errorf("Raw stat=0: %+v", rep.Stats)
	}
}

func TestEngineRunPreFiltersAndSuppressions(t *testing.T) {
	var calls int64
	srv := fakeOpenAIServer(t, &calls)
	cfg := configForServer(t, srv.URL)
	cfg.Precision.SecretsPreFilter = true
	cfg.Precision.PreFilterWatchlist = false
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "secrets.py"),
		"# llmscan:ignore[*] reason: test secret\n"+
			"KEY = 'AKIAIOSFODNN7EXAMPLE'\nPASS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n")
	e := New(cfg)
	rep, err := e.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// At least the secret pre-filter should have produced detections.
	if rep.FilesScanned == 0 {
		t.Error("no files scanned")
	}
	// Some findings (or none if suppressed) — we just exercise the code paths.
	_ = rep
}

// confirm the goroutine-based scanner code is being exercised without race.
func TestEngineRunsScannersConcurrently(t *testing.T) {
	srv := fakeOpenAIServer(t, nil)
	cfg := configForServer(t, srv.URL)
	target := writeRepoFixture(t)
	// Add a few extra files to ensure we cover the chunking + parallel paths.
	for i := 0; i < 4; i++ {
		mustWrite(t, filepath.Join(target, "more"+itoa(i)+".go"), "package x\nfunc F"+itoa(i)+"() {}\n")
	}
	e := New(cfg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := e.Run(context.Background(), target)
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	wg.Wait()
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{digits[i%10]}, out...)
		i /= 10
	}
	return string(out)
}

func TestApplyBaselineNoCacheNoOp(t *testing.T) {
	e := New(config.Default())
	in := []types.Finding{{ID: "x"}}
	out := e.applyBaseline(nil, in)
	if len(out) != 1 || out[0].ID != "x" {
		t.Errorf("nil cache should be no-op; got %+v", out)
	}
}
