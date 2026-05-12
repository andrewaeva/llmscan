package llm

import "errors"

// Sentinel errors used by all providers. Callers can switch on these with
// errors.Is to make decisions (retry, backoff, surface to user, etc).
//
// Wrap them with fmt.Errorf("...: %w", Err...) — never replace with a string.
var (
	// ErrRateLimit indicates the upstream LLM provider returned a 429 or an
	// equivalent "slow down" signal. Callers should backoff before retrying.
	ErrRateLimit = errors.New("llm: rate limit")

	// ErrAuth indicates the upstream LLM provider returned a 401/403 or
	// flagged the API key as invalid/missing.
	ErrAuth = errors.New("llm: authentication failed")

	// ErrServer indicates the upstream LLM provider returned a 5xx and the
	// caller may retry.
	ErrServer = errors.New("llm: server error")

	// ErrBadRequest indicates a 4xx other than 401/403/429 — usually a
	// permanent error in the request payload. Retrying will not help.
	ErrBadRequest = errors.New("llm: bad request")

	// ErrEmptyResponse indicates the provider returned a 2xx with no usable
	// content (e.g. empty choices, finish_reason=length and no text).
	ErrEmptyResponse = errors.New("llm: empty response")

	// ErrInvalidJSON indicates the model output that was supposed to be JSON
	// could not be parsed even after the configured retries.
	ErrInvalidJSON = errors.New("llm: invalid JSON")

	// ErrToolHandlerNil indicates a tool-call API was invoked without a
	// handler — a programming error in the caller.
	ErrToolHandlerNil = errors.New("llm: nil tool handler")
)

// classifyHTTP returns the sentinel error matching an HTTP status, or nil
// for 2xx. Callers should wrap it with fmt.Errorf("%s http %d: %s: %w", ...).
func classifyHTTP(status int) error {
	switch {
	case status == 429:
		return ErrRateLimit
	case status == 401 || status == 403:
		return ErrAuth
	case status >= 500:
		return ErrServer
	case status >= 400:
		return ErrBadRequest
	}
	return nil
}
