// Package ast wraps tree-sitter and provides a unified API to parse files and
// extract symbols, imports, function definitions and call sites.
package ast

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	tsts "github.com/smacker/go-tree-sitter/typescript/typescript"
)

// Language identifies a supported source language.
type Language string

const (
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangJava       Language = "java"
	LangUnknown    Language = ""
)

// Detect picks a language from a file path. Returns LangUnknown if unsupported.
func Detect(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return LangGo
	case ".py":
		return LangPython
	case ".js", ".jsx", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".java":
		return LangJava
	}
	return LangUnknown
}

func grammar(l Language) *sitter.Language {
	switch l {
	case LangGo:
		return golang.GetLanguage()
	case LangPython:
		return python.GetLanguage()
	case LangJavaScript:
		return javascript.GetLanguage()
	case LangTypeScript:
		return tsts.GetLanguage()
	case LangJava:
		return java.GetLanguage()
	}
	return nil
}

// Symbol describes a top-level identifier discovered in a file.
type Symbol struct {
	Kind      string `json:"kind"` // "function" | "method" | "class" | "var" | "const"
	Name      string `json:"name"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Receiver  string `json:"receiver,omitempty"`
}

// Import describes an import statement.
type Import struct {
	Path  string `json:"path"`            // raw import path, e.g. "fmt", "./util", "lodash"
	Alias string `json:"alias,omitempty"` // local alias if any
	Line  int    `json:"line"`
}

// Call is a call expression: who called what.
type Call struct {
	Callee string `json:"callee"` // textual representation (best-effort)
	Line   int    `json:"line"`
}

// FileAST is the result of parsing one file.
type FileAST struct {
	Path     string    `json:"path"`
	Language Language  `json:"language"`
	Imports  []Import  `json:"imports"`
	Symbols  []Symbol  `json:"symbols"`
	Calls    []Call    `json:"calls"`
	LOC      int       `json:"loc"`
	root     *sitter.Node
	source   []byte
}

// FileSource returns the source bytes used to parse the file.
func FileSource(f *FileAST) []byte {
	if f == nil {
		return nil
	}
	return f.source
}

// Parser is reusable; safe for sequential use. For parallel use create one per goroutine.
type Parser struct {
	p *sitter.Parser
}

// NewParser returns a fresh parser.
func NewParser() *Parser { return &Parser{p: sitter.NewParser()} }

var parserPool = sync.Pool{New: func() any { return NewParser() }}

// Parse parses the given source. Returns a FileAST or an error.
func Parse(ctx context.Context, path string, src []byte) (*FileAST, error) {
	lang := Detect(path)
	if lang == LangUnknown {
		return nil, fmt.Errorf("unsupported language for %s", path)
	}
	g := grammar(lang)
	if g == nil {
		return nil, fmt.Errorf("no grammar loaded for %s", lang)
	}
	p := parserPool.Get().(*Parser)
	defer parserPool.Put(p)
	p.p.SetLanguage(g)
	tree, err := p.p.ParseCtx(ctx, nil, src)
	if err != nil {
		return nil, err
	}
	root := tree.RootNode()
	f := &FileAST{
		Path:     path,
		Language: lang,
		LOC:      strings.Count(string(src), "\n") + 1,
		root:     root,
		source:   src,
	}
	extract(root, src, lang, f)
	return f, nil
}

// nodeText returns the source bytes covered by n.
func nodeText(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return string(src[n.StartByte():n.EndByte()])
}

func line(n *sitter.Node) int { return int(n.StartPoint().Row) + 1 }

// extract dispatches per language extractors. Each extractor is a focused walk
// rather than a generic visitor: tree-sitter node kind names differ a lot.
func extract(root *sitter.Node, src []byte, lang Language, out *FileAST) {
	switch lang {
	case LangGo:
		extractGo(root, src, out)
	case LangPython:
		extractPython(root, src, out)
	case LangJavaScript, LangTypeScript:
		extractJS(root, src, out)
	case LangJava:
		extractJava(root, src, out)
	}
}

func walk(n *sitter.Node, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), fn)
	}
}

// ---------- Go ----------

func extractGo(root *sitter.Node, src []byte, out *FileAST) {
	walk(root, func(n *sitter.Node) {
		switch n.Type() {
		case "import_spec":
			path := n.ChildByFieldName("path")
			alias := n.ChildByFieldName("name")
			imp := Import{Line: line(n)}
			if path != nil {
				imp.Path = strings.Trim(nodeText(path, src), `"`)
			}
			if alias != nil {
				imp.Alias = nodeText(alias, src)
			}
			out.Imports = append(out.Imports, imp)
		case "function_declaration":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "function", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "method_declaration":
			name := n.ChildByFieldName("name")
			recv := n.ChildByFieldName("receiver")
			sym := Symbol{Kind: "method", StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1}
			if name != nil {
				sym.Name = nodeText(name, src)
			}
			if recv != nil {
				sym.Receiver = strings.TrimSpace(nodeText(recv, src))
			}
			out.Symbols = append(out.Symbols, sym)
		case "call_expression":
			fn := n.ChildByFieldName("function")
			if fn != nil {
				out.Calls = append(out.Calls, Call{Callee: nodeText(fn, src), Line: line(n)})
			}
		}
	})
}

// ---------- Python ----------

func extractPython(root *sitter.Node, src []byte, out *FileAST) {
	walk(root, func(n *sitter.Node) {
		switch n.Type() {
		case "import_statement":
			// import a, b as c
			for i := 0; i < int(n.NamedChildCount()); i++ {
				ch := n.NamedChild(i)
				out.Imports = append(out.Imports, Import{Path: strings.TrimSpace(nodeText(ch, src)), Line: line(n)})
			}
		case "import_from_statement":
			mod := n.ChildByFieldName("module_name")
			path := ""
			if mod != nil {
				path = nodeText(mod, src)
			}
			out.Imports = append(out.Imports, Import{Path: path, Line: line(n)})
		case "function_definition":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "function", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "class_definition":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "class", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "call":
			fn := n.ChildByFieldName("function")
			if fn != nil {
				out.Calls = append(out.Calls, Call{Callee: nodeText(fn, src), Line: line(n)})
			}
		}
	})
}

// ---------- JS / TS ----------

func extractJS(root *sitter.Node, src []byte, out *FileAST) {
	walk(root, func(n *sitter.Node) {
		switch n.Type() {
		case "import_statement":
			src2 := n.ChildByFieldName("source")
			if src2 != nil {
				out.Imports = append(out.Imports, Import{Path: strings.Trim(nodeText(src2, src), `'"`), Line: line(n)})
			}
		case "call_expression":
			fn := n.ChildByFieldName("function")
			if fn != nil {
				txt := nodeText(fn, src)
				if txt == "require" {
					// require('x')
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						a := args.NamedChild(0)
						out.Imports = append(out.Imports, Import{Path: strings.Trim(nodeText(a, src), `'"`), Line: line(n)})
					}
				}
				out.Calls = append(out.Calls, Call{Callee: txt, Line: line(n)})
			}
		case "function_declaration", "method_definition":
			name := n.ChildByFieldName("name")
			kind := "function"
			if n.Type() == "method_definition" {
				kind = "method"
			}
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: kind, Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "class_declaration":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "class", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		}
	})
}

// ---------- Java ----------

func extractJava(root *sitter.Node, src []byte, out *FileAST) {
	walk(root, func(n *sitter.Node) {
		switch n.Type() {
		case "import_declaration":
			// the import path is the textual node body minus 'import ;'
			t := nodeText(n, src)
			t = strings.TrimPrefix(t, "import ")
			t = strings.TrimSuffix(strings.TrimSpace(t), ";")
			out.Imports = append(out.Imports, Import{Path: strings.TrimSpace(t), Line: line(n)})
		case "method_declaration":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "method", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "class_declaration", "interface_declaration":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Symbols = append(out.Symbols, Symbol{
					Kind: "class", Name: nodeText(name, src),
					StartLine: line(n), EndLine: int(n.EndPoint().Row) + 1,
				})
			}
		case "method_invocation":
			name := n.ChildByFieldName("name")
			if name != nil {
				out.Calls = append(out.Calls, Call{Callee: nodeText(name, src), Line: line(n)})
			}
		}
	})
}

// FunctionAtLine returns the symbol whose [start_line..end_line] contains `line`,
// preferring the innermost match. Useful for verifier context expansion.
func (f *FileAST) FunctionAtLine(ln int) *Symbol {
	var best *Symbol
	bestLen := 0
	for i := range f.Symbols {
		s := &f.Symbols[i]
		if s.StartLine <= ln && ln <= s.EndLine {
			l := s.EndLine - s.StartLine
			if best == nil || l < bestLen {
				best = s
				bestLen = l
			}
		}
	}
	return best
}
