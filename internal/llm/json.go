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
	return Response{}, nil, fmt.Errorf("llm: invalid JSON after %d retries (%v): %w", retries, lastErr, ErrInvalidJSON)
}

// ExtractJSON pulls a JSON object (or array) out of a possibly noisy LLM
// response. Handles markdown fences and trailing prose; uses a brace-aware
// scan to cut exactly at the matching closing delimiter (string-literal /
// escape aware) so trailing content like double-encoded JSON or chatty
// epilogues do not break json.Unmarshal.
func ExtractJSON(s string) string {
	s = stripCodeFence(strings.TrimSpace(s))
	start, open, closer := firstDelim(s)
	if start < 0 {
		return s
	}
	if end := matchDelim(s, start, open, closer); end > start {
		return s[start : end+1]
	}
	// Unbalanced — fall back to greedy first..last.
	if j := strings.LastIndexAny(s, "}]"); j > start {
		return s[start : j+1]
	}
	return s[start:]
}

// stripCodeFence removes a leading ```lang fence and its trailing ``` if present.
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if j := strings.LastIndex(s, "```"); j >= 0 {
		s = s[:j]
	}
	return strings.TrimSpace(s)
}

// firstDelim returns the index of the first '{' or '[' plus the matching
// open/close byte pair. start is -1 when neither is found.
func firstDelim(s string) (start int, open, closer byte) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			return i, '{', '}'
		case '[':
			return i, '[', ']'
		}
	}
	return -1, 0, 0
}

// matchDelim scans from start and returns the index of the closer that balances
// the open delimiter, respecting string literals and escapes. Returns -1 when
// unbalanced.
func matchDelim(s string, start int, open, closer byte) int {
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
