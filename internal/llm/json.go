package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CompleteJSON runs Complete with JSON-mode and validates that the response is
// parseable JSON. On invalid JSON it retries up to `retries` times, feeding the
// previous error back to the model as an assistant/user correction pair.
func CompleteJSON(ctx context.Context, c Client, req Request, retries int) (Response, []byte, error) {
	req.JSON = true
	var lastErr error
	for i := 0; i <= retries; i++ {
		resp, err := c.Complete(ctx, req)
		if err != nil {
			return resp, nil, err
		}
		js := ExtractJSON(resp.Text)
		var probe any
		jerr := json.Unmarshal([]byte(js), &probe)
		if jerr == nil {
			return resp, []byte(js), nil
		}
		lastErr = jerr
		req.Messages = append(req.Messages,
			Message{Role: "assistant", Content: resp.Text},
			Message{Role: "user", Content: fmt.Sprintf(
				"Your previous response was not valid JSON (%v). Return ONLY a JSON object, no prose, no markdown.",
				jerr)},
		)
	}
	return Response{}, nil, fmt.Errorf("llm: invalid JSON after %d retries: %w", retries, lastErr)
}

// ExtractJSON pulls a JSON object out of a possibly noisy LLM response (handles markdown fences).
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// strip first fence line
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		if j := strings.LastIndex(s, "```"); j >= 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	// fall back to first '{' .. last '}'
	if !strings.HasPrefix(s, "{") {
		if i := strings.Index(s, "{"); i >= 0 {
			if j := strings.LastIndex(s, "}"); j > i {
				s = s[i : j+1]
			}
		}
	}
	return s
}
