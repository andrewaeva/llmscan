package contextpack

import (
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/tokens"
)

// dedupe merges fragments that point to the same source range. Two fragments
// are considered duplicates iff:
//
//   - same File, AND
//   - their [Start,End] ranges overlap.
//
// Overlapping fragments are coalesced into a single fragment covering the
// union; the lowest priority wins (most important wins); reasons are joined.
//
// Fragments whose range overlaps the chunk itself are dropped — the chunk
// already covers them.
//
// The result preserves a deterministic order: by (File, Start, End).
func dedupe(in []Fragment, chunk Fragment) []Fragment {
	if len(in) == 0 {
		return in
	}
	// 1) Filter out anything overlapping the chunk.
	filtered := in[:0:0]
	for _, f := range in {
		if f.File == chunk.File && rangesOverlap(f.Start, f.End, chunk.Start, chunk.End) {
			continue
		}
		filtered = append(filtered, f)
	}
	if len(filtered) == 0 {
		return nil
	}

	// 2) Group by file, then merge overlapping ranges within each group.
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].File != filtered[j].File {
			return filtered[i].File < filtered[j].File
		}
		if filtered[i].Start != filtered[j].Start {
			return filtered[i].Start < filtered[j].Start
		}
		return filtered[i].End < filtered[j].End
	})

	out := make([]Fragment, 0, len(filtered))
	cur := filtered[0]
	curReasons := map[string]bool{cur.Reason: true}
	curKinds := map[FragmentKind]bool{cur.Kind: true}
	for i := 1; i < len(filtered); i++ {
		nxt := filtered[i]
		if nxt.File == cur.File && rangesOverlap(cur.Start, cur.End, nxt.Start, nxt.End) {
			cur = mergePair(cur, nxt)
			curReasons[nxt.Reason] = true
			curKinds[nxt.Kind] = true
			continue
		}
		out = append(out, finaliseMerge(cur, curReasons, curKinds))
		cur = nxt
		curReasons = map[string]bool{nxt.Reason: true}
		curKinds = map[FragmentKind]bool{nxt.Kind: true}
	}
	out = append(out, finaliseMerge(cur, curReasons, curKinds))
	return out
}

func mergePair(a, b Fragment) Fragment {
	// Larger range wins for Code; lowest Priority (=most important) wins.
	prio := a.Priority
	if b.Priority < prio {
		prio = b.Priority
	}
	lo := a.Start
	if b.Start < lo {
		lo = b.Start
	}
	hi := a.End
	if b.End > hi {
		hi = b.End
	}
	code := a.Code
	if len(b.Code) > len(a.Code) {
		code = b.Code
	}
	sym := a.Symbol
	if sym == "" {
		sym = b.Symbol
	}
	return Fragment{
		Kind:     a.Kind, // dominant kind decided in finaliseMerge
		File:     a.File,
		Symbol:   sym,
		Start:    lo,
		End:      hi,
		Code:     code,
		Priority: prio,
		Tokens:   tokens.Estimate(code),
	}
}

func finaliseMerge(f Fragment, reasons map[string]bool, kinds map[FragmentKind]bool) Fragment {
	// Pick the most important kind (callee > caller > type > sanitizer > rag >
	// const > sibling). This influences only display grouping in Render().
	ord := []FragmentKind{
		KindCallee, KindCaller, KindType, KindSanitizer,
		KindConst, KindRAG, KindSibling,
	}
	for _, k := range ord {
		if kinds[k] {
			f.Kind = k
			break
		}
	}
	if len(reasons) > 1 {
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			if r == "" {
				continue
			}
			rs = append(rs, r)
		}
		sort.Strings(rs)
		f.Reason = strings.Join(rs, " + ")
	}
	return f
}

func rangesOverlap(a1, a2, b1, b2 int) bool {
	return a1 <= b2 && b1 <= a2
}

// squeeze truncates an oversized fragment to fit within budget. Keeps the
// signature lines (head) plus the last few lines (often the return/closing
// guard), inserting a marker for the elided middle. Returns a new Fragment
// flagged Squeezed=true with refreshed Tokens.
func (b *Builder) squeeze(f Fragment, budget int) Fragment {
	if f.Tokens <= budget {
		return f
	}
	lines := strings.Split(f.Code, "\n")
	head := b.Cfg.SqueezeHeadLines
	tail := b.Cfg.SqueezeTailLines
	if head <= 0 {
		head = 40
	}
	if tail <= 0 {
		tail = 20
	}
	// Shrink head/tail proportionally until we fit. Refuse below 5/5.
	for {
		if head < 5 || tail < 5 {
			head = 5
			tail = 5
		}
		if head+tail >= len(lines) {
			// Fragment is short enough textually but token estimate was off.
			f.Squeezed = true
			f.Tokens = tokens.Estimate(f.Code)
			return f
		}
		var sb strings.Builder
		sb.Grow(len(f.Code) / 4)
		for i := 0; i < head && i < len(lines); i++ {
			sb.WriteString(lines[i])
			sb.WriteByte('\n')
		}
		omitted := len(lines) - head - tail
		if omitted > 0 {
			sb.WriteString("// ... (")
			sb.WriteString(itoa(omitted))
			sb.WriteString(" lines elided to fit context budget) ...\n")
		}
		for i := len(lines) - tail; i < len(lines); i++ {
			if i < head {
				continue
			}
			sb.WriteString(lines[i])
			sb.WriteByte('\n')
		}
		code := sb.String()
		tk := tokens.Estimate(code)
		if tk <= budget || (head <= 5 && tail <= 5) {
			f.Code = code
			f.Tokens = tk
			f.Squeezed = true
			return f
		}
		// shrink further
		head = head * 3 / 4
		tail = tail * 3 / 4
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
