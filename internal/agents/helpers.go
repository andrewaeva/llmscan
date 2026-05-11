package agents

import (
	"encoding/json"
	"strings"
)

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func emptyIf(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func hash6(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 6)
	for i := range out {
		out[i] = abc[h%uint32(len(abc))]
		h /= uint32(len(abc))
		if h == 0 {
			h = 2166136261 ^ uint32(i)
		}
	}
	return string(out)
}
