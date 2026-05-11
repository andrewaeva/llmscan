package report

import (
	"io"
	"os"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// ColorMode controls ANSI coloring of the text report.
type ColorMode int

const (
	ColorAuto ColorMode = iota
	ColorAlways
	ColorNever
)

// ParseColorMode parses "auto" | "always" | "never" (case-insensitive).
// Unknown values fall back to ColorAuto.
func ParseColorMode(s string) ColorMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "always", "yes", "on", "true", "1":
		return ColorAlways
	case "never", "no", "off", "false", "0":
		return ColorNever
	default:
		return ColorAuto
	}
}

// resolveColor decides whether to emit ANSI escapes for the given writer.
// Auto mode: enabled only when writer is a real TTY and NO_COLOR is unset.
// Honors CLICOLOR_FORCE=1 to override auto-detection.
func resolveColor(w io.Writer, mode ColorMode) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ANSI escape codes (no external deps).
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiItalic  = "\x1b[3m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
	ansiGray    = "\x1b[90m"
	ansiBgRed   = "\x1b[41m"
)

type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (p palette) bold(s string) string      { return p.wrap(ansiBold, s) }
func (p palette) dim(s string) string       { return p.wrap(ansiDim, s) }
func (p palette) italic(s string) string    { return p.wrap(ansiItalic, s) }
func (p palette) red(s string) string       { return p.wrap(ansiRed, s) }
func (p palette) green(s string) string     { return p.wrap(ansiGreen, s) }
func (p palette) yellow(s string) string    { return p.wrap(ansiYellow, s) }
func (p palette) blue(s string) string      { return p.wrap(ansiBlue, s) }
func (p palette) magenta(s string) string   { return p.wrap(ansiMagenta, s) }
func (p palette) cyan(s string) string      { return p.wrap(ansiCyan, s) }
func (p palette) gray(s string) string      { return p.wrap(ansiGray, s) }

// sevBadge renders "[ CRITICAL ]" / "[ HIGH ]" / ... with severity-appropriate
// coloring. For critical it uses a red background to stand out.
func (p palette) sevBadge(s types.Severity) string {
	label := strings.ToUpper(string(s))
	if label == "" {
		label = "UNKNOWN"
	}
	badge := " " + label + " "
	if !p.on {
		return "[" + label + "]"
	}
	switch s {
	case types.SevCritical:
		return ansiBold + ansiBgRed + "\x1b[97m" + badge + ansiReset
	case types.SevHigh:
		return ansiBold + ansiRed + "[" + label + "]" + ansiReset
	case types.SevMedium:
		return ansiBold + ansiYellow + "[" + label + "]" + ansiReset
	case types.SevLow:
		return ansiBold + ansiBlue + "[" + label + "]" + ansiReset
	case types.SevInfo:
		return ansiDim + "[" + label + "]" + ansiReset
	}
	return "[" + label + "]"
}

// confColor colors confidence text by level (high=green, medium=yellow, low=gray).
func (p palette) confColor(c string) string {
	if !p.on {
		return string(c)
	}
	switch strings.ToLower(string(c)) {
	case "high":
		return p.green(string(c))
	case "medium":
		return p.yellow(string(c))
	case "low":
		return p.gray(string(c))
	}
	return string(c)
}
