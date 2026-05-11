// Package entrypoints detects program entry points across supported languages.
//
// An entry point is any function that receives data from the outside world:
// HTTP/gRPC handlers, CLI command bodies, message-queue consumers, scheduled
// jobs, exported library APIs. They are the "sources of sources" for
// inter-procedural taint analysis — every parameter is conservatively treated
// as attacker-controllable.
//
// Detection is pattern-based and runs on parsed file ASTs plus the original
// source text. We deliberately err toward over-detection: better to start a
// few extra taint walks than miss a real entry point.
package entrypoints

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
)

// Kind groups detected entry points by surface.
type Kind string

const (
	KindHTTP      Kind = "http"
	KindCLI       Kind = "cli"
	KindRPC       Kind = "rpc"
	KindConsumer  Kind = "consumer"
	KindScheduled Kind = "scheduled"
	KindExported  Kind = "exported"
)

// Info describes one detected entry point.
type Info struct {
	Node           callgraph.NodeID `json:"node"`
	File           string           `json:"file"`
	Func           string           `json:"func"`
	Kind           Kind             `json:"kind"`
	Reason         string           `json:"reason"`
	ConfidenceHint float64          `json:"confidence_hint"`
}

// Detect scans every parsed file and returns detected entry points. The
// returned slice is stable-sorted by (file, line).
func Detect(files []*ast.FileAST) []Info {
	var out []Info
	for _, f := range files {
		if f == nil {
			continue
		}
		src := string(ast.FileSource(f))
		switch f.Language {
		case ast.LangGo:
			out = append(out, detectGo(f, src)...)
		case ast.LangPython:
			out = append(out, detectPython(f, src)...)
		case ast.LangJavaScript, ast.LangTypeScript:
			out = append(out, detectJS(f, src)...)
		case ast.LangJava:
			out = append(out, detectJava(f, src)...)
		}
	}
	// Dedup by (file, func): one func is one entry, even if multiple patterns matched.
	seen := map[string]int{}
	dedup := out[:0]
	for _, e := range out {
		key := e.File + "::" + e.Func
		if idx, ok := seen[key]; ok {
			if e.ConfidenceHint > dedup[idx].ConfidenceHint {
				dedup[idx] = e
			}
			continue
		}
		seen[key] = len(dedup)
		dedup = append(dedup, e)
	}
	sort.Slice(dedup, func(i, j int) bool {
		if dedup[i].File != dedup[j].File {
			return dedup[i].File < dedup[j].File
		}
		return dedup[i].Func < dedup[j].Func
	})
	return dedup
}

// IDs returns the NodeIDs of all detected entry points.
func IDs(eps []Info) []callgraph.NodeID {
	ids := make([]callgraph.NodeID, 0, len(eps))
	for _, e := range eps {
		ids = append(ids, e.Node)
	}
	return ids
}

// ----- helpers -----

func srcLine(src string, ln int) string {
	if ln <= 0 {
		return ""
	}
	lines := strings.SplitN(src, "\n", ln+1)
	if len(lines) < ln {
		return ""
	}
	return lines[ln-1]
}

// sliceOf returns the source bytes between [start, end] (1-based, inclusive).
func sliceOf(src string, start, end int) string {
	lines := strings.Split(src, "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return ""
	}
	return strings.Join(lines[start-1:end], "\n")
}

// previousNonBlankLine returns the source line above `ln` skipping blanks.
func previousNonBlankLine(src string, ln int) string {
	for ln > 1 {
		ln--
		s := strings.TrimSpace(srcLine(src, ln))
		if s != "" {
			return s
		}
	}
	return ""
}

// ----- Go -----

var (
	reGoHTTPHandler = regexp.MustCompile(`\bhttp\.ResponseWriter\b|\*http\.Request\b`)
	reGoGin         = regexp.MustCompile(`\*gin\.Context\b|gin\.HandlerFunc\b`)
	reGoEcho        = regexp.MustCompile(`echo\.Context\b`)
	reGoFiber       = regexp.MustCompile(`\*fiber\.Ctx\b`)
	reGoConsumer    = regexp.MustCompile(`(?i)^(Consume|OnMessage|Handle|Handler|Process|Worker)$`)
	reGoMainPkg     = regexp.MustCompile(`(?m)^package\s+main\b`)
)

//nolint:gocyclo // many regex/framework patterns; flat switch is intentional
func detectGo(f *ast.FileAST, src string) []Info {
	var out []Info
	hasMainPkg := reGoMainPkg.MatchString(src)
	for i := range f.Symbols {
		s := &f.Symbols[i]
		if s.Kind != "function" && s.Kind != "method" {
			continue
		}
		sig := srcLine(src, s.StartLine)
		body := sliceOf(src, s.StartLine, min(s.StartLine+4, s.EndLine))
		switch {
		case reGoHTTPHandler.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "net/http handler signature", ConfidenceHint: 0.95})
		case reGoGin.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "gin handler", ConfidenceHint: 0.9})
		case reGoEcho.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "echo handler", ConfidenceHint: 0.9})
		case reGoFiber.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "fiber handler", ConfidenceHint: 0.9})
		case s.Name == "main" && hasMainPkg:
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindCLI, Reason: "main package entry", ConfidenceHint: 0.95})
		case reGoConsumer.MatchString(s.Name):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindConsumer, Reason: "consumer-like name", ConfidenceHint: 0.55})
		case strings.Contains(body, "cobra.Command") || strings.Contains(body, "RunE:") && s.Name != "":
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindCLI, Reason: "cobra Run/RunE body", ConfidenceHint: 0.7})
		case isExportedGo(s.Name) && isPublicPath(f.Path):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindExported, Reason: "exported in pkg/", ConfidenceHint: 0.4})
		}
	}
	return out
}

func isExportedGo(name string) bool {
	return name != "" && name[0] >= 'A' && name[0] <= 'Z'
}

func isPublicPath(p string) bool {
	p = strings.ToLower(filepath.ToSlash(p))
	return strings.Contains(p, "/pkg/") || strings.HasPrefix(p, "pkg/")
}

// ----- Python -----

var (
	rePyRoute     = regexp.MustCompile(`@\w*(app|router|api|blueprint)\.(route|get|post|put|patch|delete|options|head|websocket)\b`)
	rePyFastAPI   = regexp.MustCompile(`@\w*\.(get|post|put|patch|delete)\(`)
	rePyClick     = regexp.MustCompile(`@\w*click\.command\b|@command\b`)
	rePyScheduled = regexp.MustCompile(`@\w*scheduled\b|@cron\b`)
	rePyConsumer  = regexp.MustCompile(`@\w*(consumer|handler|task|listener|subscribe|on_message)\b`)
)

func detectPython(f *ast.FileAST, src string) []Info {
	var out []Info
	for i := range f.Symbols {
		s := &f.Symbols[i]
		if s.Kind != "function" {
			continue
		}
		dec := previousNonBlankLine(src, s.StartLine)
		switch {
		case rePyRoute.MatchString(dec) || rePyFastAPI.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "@route/@get/@post decorator", ConfidenceHint: 0.9})
		case rePyClick.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindCLI, Reason: "click command", ConfidenceHint: 0.85})
		case rePyScheduled.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindScheduled, Reason: "scheduled/cron decorator", ConfidenceHint: 0.8})
		case rePyConsumer.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindConsumer, Reason: "consumer/handler decorator", ConfidenceHint: 0.7})
		case s.Name == "main":
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindCLI, Reason: "main function", ConfidenceHint: 0.6})
		case strings.HasSuffix(strings.ToLower(filepath.ToSlash(f.Path)), "__init__.py") && !strings.HasPrefix(s.Name, "_"):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindExported, Reason: "re-export from __init__.py", ConfidenceHint: 0.4})
		}
	}
	return out
}

// ----- JS / TS -----

var (
	reJSRouter      = regexp.MustCompile(`\b(app|router)\.(get|post|put|patch|delete|use|all|head|options|ws)\s*\(`)
	reJSHandler     = regexp.MustCompile(`\((req|request)\s*[,)].*?(res|response)\s*[,)]?`)
	reJSKoa         = regexp.MustCompile(`\bctx\.(request|body|query|params)\b`)
	reJSExportTop   = regexp.MustCompile(`(?m)^\s*export\s+(default\s+)?(async\s+)?function\b`)
	reJSCronWrap    = regexp.MustCompile(`\b(cron\.schedule|setInterval|setTimeout)\s*\(`)
	reJSConsumer    = regexp.MustCompile(`(?i)on(Message|Event|Request|Connect)|consume|handler`)
	reJSExportedTop = regexp.MustCompile(`(?m)^\s*export\s+`)
)

func detectJS(f *ast.FileAST, src string) []Info {
	var out []Info
	for i := range f.Symbols {
		s := &f.Symbols[i]
		if s.Kind != "function" && s.Kind != "method" {
			continue
		}
		sig := srcLine(src, s.StartLine)
		body := sliceOf(src, s.StartLine, min(s.StartLine+3, s.EndLine))
		// Look up to 3 lines above for a "router.get('/x', handler)" registration.
		above := ""
		if s.StartLine > 1 {
			above = sliceOf(src, max(1, s.StartLine-3), s.StartLine-1)
		}
		switch {
		case reJSRouter.MatchString(above) || reJSRouter.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "express/koa route registration", ConfidenceHint: 0.85})
		case reJSHandler.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "(req, res, ...) handler signature", ConfidenceHint: 0.7})
		case reJSKoa.MatchString(body):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "koa ctx usage", ConfidenceHint: 0.7})
		case reJSCronWrap.MatchString(above):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindScheduled, Reason: "cron/setInterval wrapper", ConfidenceHint: 0.6})
		case reJSConsumer.MatchString(s.Name):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindConsumer, Reason: "consumer-like name", ConfidenceHint: 0.55})
		case reJSExportTop.MatchString(above + "\n" + sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindExported, Reason: "exported top-level function", ConfidenceHint: 0.4})
		}
	}
	_ = reJSExportedTop
	return out
}

// ----- Java -----

var (
	reJavaMapping = regexp.MustCompile(`@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|PatchMapping)\b`)
	reJavaCtrl    = regexp.MustCompile(`@(RestController|Controller)\b`)
	reJavaSched   = regexp.MustCompile(`@Scheduled\b`)
	reJavaMain    = regexp.MustCompile(`public\s+static\s+void\s+main\s*\(`)
)

func detectJava(f *ast.FileAST, src string) []Info {
	var out []Info
	classCtrl := reJavaCtrl.MatchString(src)
	for i := range f.Symbols {
		s := &f.Symbols[i]
		if s.Kind != "method" {
			continue
		}
		// Java's tree-sitter often includes annotations inside the method node, so
		// scan the full symbol body plus the line above to be safe.
		decRange := sliceOf(src, max(1, s.StartLine-1), min(s.EndLine, s.StartLine+1))
		dec := previousNonBlankLine(src, s.StartLine) + "\n" + decRange
		sig := srcLine(src, s.StartLine)
		// If the start line itself is an annotation, also include the next non-blank line as the real signature.
		if strings.HasPrefix(strings.TrimSpace(sig), "@") {
			for ln := s.StartLine + 1; ln <= s.EndLine; ln++ {
				cand := srcLine(src, ln)
				if strings.TrimSpace(cand) != "" && !strings.HasPrefix(strings.TrimSpace(cand), "@") {
					sig = cand
					break
				}
			}
		}
		switch {
		case reJavaMapping.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "@*Mapping annotation", ConfidenceHint: 0.92})
		case classCtrl && (strings.Contains(sig, "public") || strings.HasPrefix(strings.TrimSpace(sig), "public")):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindHTTP, Reason: "public method in @RestController", ConfidenceHint: 0.55})
		case reJavaSched.MatchString(dec):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindScheduled, Reason: "@Scheduled", ConfidenceHint: 0.8})
		case reJavaMain.MatchString(sig):
			out = append(out, Info{Node: callgraph.IDOf(f.Path, s.Name), File: f.Path, Func: s.Name, Kind: KindCLI, Reason: "public static void main", ConfidenceHint: 0.95})
		}
	}
	return out
}

// (intentionally empty — Go 1.21+ has builtin min/max)
