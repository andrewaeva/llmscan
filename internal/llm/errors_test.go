package llm

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{200, nil},
		{204, nil},
		{299, nil},
		{400, ErrBadRequest},
		{404, ErrBadRequest},
		{401, ErrAuth},
		{403, ErrAuth},
		{429, ErrRateLimit},
		{500, ErrServer},
		{502, ErrServer},
		{599, ErrServer},
	}
	for _, tc := range cases {
		got := classifyHTTP(tc.status)
		if got != tc.want {
			t.Errorf("classifyHTTP(%d)=%v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	all := []error{
		ErrRateLimit, ErrAuth, ErrServer, ErrBadRequest,
		ErrEmptyResponse, ErrInvalidJSON, ErrToolHandlerNil,
	}
	for i, a := range all {
		for j, b := range all {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %v should not Is %v", a, b)
			}
		}
	}
}

func TestSentinelErrors_WrapUnwraps(t *testing.T) {
	wrapped := fmt.Errorf("upstream said no: %w", ErrRateLimit)
	if !errors.Is(wrapped, ErrRateLimit) {
		t.Error("wrapped error should Is ErrRateLimit")
	}
	if errors.Is(wrapped, ErrAuth) {
		t.Error("wrapped error should not Is unrelated sentinel")
	}
}
