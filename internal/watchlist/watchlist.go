// Package watchlist defines per-language sources, sinks and sanitizers.
// It powers three v3 features:
//   - tree-sitter pre-filter (skip files with zero dangerous calls);
//   - lightweight taint tracking (source -> ... -> sink);
//   - sanitizer-awareness (downgrade findings sanitized between source and sink).
//
// The lists are intentionally curated and conservative — high precision over
// recall. Extend per project via SKILL.md or YAML override (future).
package watchlist

// Kind classifies a watchlist entry.
type Kind string

const (
	KindSource    Kind = "source"
	KindSink      Kind = "sink"
	KindSanitizer Kind = "sanitizer"
)

// Entry is a single matcher. Match is currently a substring match on call
// text — fast and good enough for an LLM-assisted pre-filter.
type Entry struct {
	Match    string
	Kind     Kind
	Category string // e.g. "sql", "command", "ssrf", "deserialization", "xss"
}

// Lang is normalized language id (must match ast.DetectLanguage outputs).
type Lang string

const (
	LangGo     Lang = "go"
	LangPython Lang = "python"
	LangJS     Lang = "javascript"
	LangTS     Lang = "typescript"
	LangJava   Lang = "java"
)

// All returns a flat list of entries for a language.
func All(lang string) []Entry {
	switch Lang(lang) {
	case LangGo:
		return goList
	case LangPython:
		return pyList
	case LangJS, LangTS:
		return jsList
	case LangJava:
		return javaList
	}
	return nil
}

// HasHit reports whether any entry of the requested kind matches the source.
// Used by the tree-sitter pre-filter to decide whether to skip a file.
func HasHit(lang, src string, kinds ...Kind) bool {
	want := map[Kind]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	if len(want) == 0 {
		want[KindSource] = true
		want[KindSink] = true
	}
	for _, e := range All(lang) {
		if !want[e.Kind] {
			continue
		}
		if containsFold(src, e.Match) {
			return true
		}
	}
	return false
}

// FindMatches returns all entries whose Match substring is present in src.
// Optional kinds filter.
func FindMatches(lang, src string, kinds ...Kind) []Entry {
	want := map[Kind]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	allKinds := len(want) == 0
	var out []Entry
	for _, e := range All(lang) {
		if !allKinds && !want[e.Kind] {
			continue
		}
		if containsFold(src, e.Match) {
			out = append(out, e)
		}
	}
	return out
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	// Case-sensitive: code is case-sensitive. Cheaper than ToLower.
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// -------- Go --------
var goList = []Entry{
	// sources
	{"r.URL.Query", KindSource, "http"},
	{"r.FormValue", KindSource, "http"},
	{"r.PostFormValue", KindSource, "http"},
	{"r.Header.Get", KindSource, "http"},
	{"mux.Vars", KindSource, "http"},
	{"c.Param", KindSource, "http"},
	{"c.Query", KindSource, "http"},
	{"os.Getenv", KindSource, "env"},
	{"flag.String", KindSource, "cli"},
	// sinks
	{"exec.Command", KindSink, "command"},
	{"exec.CommandContext", KindSink, "command"},
	{"syscall.Exec", KindSink, "command"},
	{"db.Query", KindSink, "sql"},
	{"db.Exec", KindSink, "sql"},
	{"db.QueryRow", KindSink, "sql"},
	{"sqlx.Select", KindSink, "sql"},
	{"http.Get", KindSink, "ssrf"},
	{"http.Post", KindSink, "ssrf"},
	{"http.NewRequest", KindSink, "ssrf"},
	{"client.Do", KindSink, "ssrf"},
	{"os.OpenFile", KindSink, "path"},
	{"ioutil.ReadFile", KindSink, "path"},
	{"os.ReadFile", KindSink, "path"},
	{"template.HTML", KindSink, "xss"},
	{"gob.NewDecoder", KindSink, "deserialization"},
	{"yaml.Unmarshal", KindSink, "deserialization"},
	// sanitizers
	{"html.EscapeString", KindSanitizer, "xss"},
	{"template.HTMLEscapeString", KindSanitizer, "xss"},
	{"url.QueryEscape", KindSanitizer, "ssrf"},
	{"strconv.Atoi", KindSanitizer, "sql"},
	{"strconv.ParseInt", KindSanitizer, "sql"},
	{"filepath.Clean", KindSanitizer, "path"},
	// prepared statements are inherently safe — flag for verifier
	{"Prepare", KindSanitizer, "sql"},
}

// -------- Python --------
var pyList = []Entry{
	// sources
	{"request.args", KindSource, "http"},
	{"request.form", KindSource, "http"},
	{"request.values", KindSource, "http"},
	{"request.json", KindSource, "http"},
	{"request.headers", KindSource, "http"},
	{"request.cookies", KindSource, "http"},
	{"request.GET", KindSource, "http"},
	{"request.POST", KindSource, "http"},
	{"os.environ", KindSource, "env"},
	{"sys.argv", KindSource, "cli"},
	{"input(", KindSource, "stdin"},
	// sinks
	{"os.system", KindSink, "command"},
	{"subprocess.call", KindSink, "command"},
	{"subprocess.Popen", KindSink, "command"},
	{"subprocess.run", KindSink, "command"},
	{"subprocess.check_output", KindSink, "command"},
	{"os.popen", KindSink, "command"},
	{"eval(", KindSink, "code-exec"},
	{"exec(", KindSink, "code-exec"},
	{"compile(", KindSink, "code-exec"},
	{"pickle.loads", KindSink, "deserialization"},
	{"pickle.load", KindSink, "deserialization"},
	{"yaml.load", KindSink, "deserialization"},
	{"marshal.loads", KindSink, "deserialization"},
	{"cursor.execute", KindSink, "sql"},
	{".raw(", KindSink, "sql"},
	{"requests.get", KindSink, "ssrf"},
	{"requests.post", KindSink, "ssrf"},
	{"urllib.request.urlopen", KindSink, "ssrf"},
	{"open(", KindSink, "path"},
	{"jinja2.Template", KindSink, "xss"},
	{"Markup(", KindSink, "xss"},
	{"render_template_string", KindSink, "xss"},
	// sanitizers
	{"shlex.quote", KindSanitizer, "command"},
	{"shlex.split", KindSanitizer, "command"},
	{"html.escape", KindSanitizer, "xss"},
	{"bleach.clean", KindSanitizer, "xss"},
	{"escape(", KindSanitizer, "xss"},
	{"yaml.safe_load", KindSanitizer, "deserialization"},
	{"json.loads", KindSanitizer, "deserialization"},
	{"int(", KindSanitizer, "sql"},
	{"float(", KindSanitizer, "sql"},
	{"urllib.parse.quote", KindSanitizer, "ssrf"},
	{"%s", KindSanitizer, "sql"}, // parameterized placeholder
	{"?", KindSanitizer, "sql"},
}

// -------- JS / TS --------
var jsList = []Entry{
	// sources
	{"req.query", KindSource, "http"},
	{"req.body", KindSource, "http"},
	{"req.params", KindSource, "http"},
	{"req.headers", KindSource, "http"},
	{"req.cookies", KindSource, "http"},
	{"document.location", KindSource, "dom"},
	{"window.location", KindSource, "dom"},
	{"location.search", KindSource, "dom"},
	{"process.env", KindSource, "env"},
	// sinks
	{"child_process.exec", KindSink, "command"},
	{"child_process.spawn", KindSink, "command"},
	{"eval(", KindSink, "code-exec"},
	{"new Function(", KindSink, "code-exec"},
	{"setTimeout(", KindSink, "code-exec"},
	{".query(", KindSink, "sql"},
	{".execute(", KindSink, "sql"},
	{".innerHTML", KindSink, "xss"},
	{"document.write", KindSink, "xss"},
	{"dangerouslySetInnerHTML", KindSink, "xss"},
	{"fetch(", KindSink, "ssrf"},
	{"axios.get", KindSink, "ssrf"},
	{"http.request", KindSink, "ssrf"},
	{"fs.readFile", KindSink, "path"},
	{"fs.writeFile", KindSink, "path"},
	// sanitizers
	{"encodeURIComponent", KindSanitizer, "ssrf"},
	{"escapeHtml", KindSanitizer, "xss"},
	{"DOMPurify.sanitize", KindSanitizer, "xss"},
	{"parseInt(", KindSanitizer, "sql"},
	{"parseFloat(", KindSanitizer, "sql"},
	{"path.normalize", KindSanitizer, "path"},
}

// -------- Java --------
var javaList = []Entry{
	// sources
	{"request.getParameter", KindSource, "http"},
	{"request.getHeader", KindSource, "http"},
	{"request.getQueryString", KindSource, "http"},
	{"request.getCookies", KindSource, "http"},
	{"System.getenv", KindSource, "env"},
	// sinks
	{"Runtime.getRuntime().exec", KindSink, "command"},
	{"ProcessBuilder", KindSink, "command"},
	{".executeQuery", KindSink, "sql"},
	{".executeUpdate", KindSink, "sql"},
	{".createStatement", KindSink, "sql"},
	{"new URL(", KindSink, "ssrf"},
	{"URLConnection", KindSink, "ssrf"},
	{"HttpClient", KindSink, "ssrf"},
	{"new File(", KindSink, "path"},
	{"FileInputStream", KindSink, "path"},
	{"ObjectInputStream", KindSink, "deserialization"},
	{".readObject()", KindSink, "deserialization"},
	{"ScriptEngine", KindSink, "code-exec"},
	// sanitizers
	{"prepareStatement", KindSanitizer, "sql"},
	{"setString", KindSanitizer, "sql"},
	{"setInt", KindSanitizer, "sql"},
	{"StringEscapeUtils.escapeHtml", KindSanitizer, "xss"},
	{"Encode.forHtml", KindSanitizer, "xss"},
	{"URLEncoder.encode", KindSanitizer, "ssrf"},
}
