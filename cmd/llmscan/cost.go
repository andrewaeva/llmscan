package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/andrewaeva/llmscan/internal/llm"
)

// costCmd: `llmscan cost --log calls.jsonl [--prices prices.yaml]`
// Aggregates a JSONL produced by --llm-log into a per-stage / per-model table.
// Without --prices, only token totals and counts are printed.
func costCmd() *cobra.Command {
	var (
		logPath    string
		pricesPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Aggregate an --llm-log JSONL into a per-stage cost/usage table",
		Long: `Reads a JSONL file produced by 'llmscan scan --llm-log <path>' and prints
per-stage and per-model token usage, call counts and (when a YAML price book
is supplied) estimated USD cost.

Price book format (USD per 1M tokens):

  models:
    claude-sonnet-4-6:        { input: 3.00,  output: 15.00 }
    gpt-5:                    { input: 2.50,  output: 10.00 }
    deepseek-v3.2:            { input: 0.27,  output: 1.10 }
    default:                  { input: 1.00,  output: 3.00 }   # fallback`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCost(logPath, pricesPath, jsonOut)
		},
	}
	cmd.Flags().StringVar(&logPath, "log", "", "Path to JSONL log file (from --llm-log)")
	cmd.Flags().StringVar(&pricesPath, "prices", "", "Optional YAML price book (USD / 1M tokens by model)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit aggregation as JSON instead of a table")
	_ = cmd.MarkFlagRequired("log")
	return cmd
}

type modelPrice struct {
	Input  float64 `yaml:"input"`
	Output float64 `yaml:"output"`
}

type priceBook struct {
	Models map[string]modelPrice `yaml:"models"`
}

func (p *priceBook) lookup(model string) (modelPrice, bool) {
	if p == nil {
		return modelPrice{}, false
	}
	if v, ok := p.Models[model]; ok {
		return v, true
	}
	if v, ok := p.Models["default"]; ok {
		return v, true
	}
	return modelPrice{}, false
}

type bucket struct {
	Stage     string  `json:"stage"`
	Model     string  `json:"model"`
	Calls     int     `json:"calls"`
	Errors    int     `json:"errors"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	LatencyMS int64   `json:"latency_ms_total"`
	USD       float64 `json:"usd,omitempty"`
}

// loadPriceBook reads an optional price list; returns nil when pricesPath is empty.
func loadPriceBook(pricesPath string) (*priceBook, error) {
	if pricesPath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(pricesPath) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read prices: %w", err)
	}
	var pb priceBook
	if err := yaml.Unmarshal(b, &pb); err != nil {
		return nil, fmt.Errorf("parse prices: %w", err)
	}
	return &pb, nil
}

// scanCostBuckets reads a JSONL llm-log and aggregates entries by stage|model.
// Returns the buckets and the count of well-formed lines.
func scanCostBuckets(logPath string) (map[string]*bucket, int, error) {
	fh, err := os.Open(logPath) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, 0, fmt.Errorf("open log: %w", err)
	}
	defer fh.Close()

	buckets := map[string]*bucket{}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lines := 0
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e llm.LogEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue // skip malformed lines
		}
		lines++
		key := e.Stage + "|" + e.Model
		b := buckets[key]
		if b == nil {
			b = &bucket{Stage: e.Stage, Model: e.Model}
			buckets[key] = b
		}
		b.Calls++
		if !e.OK {
			b.Errors++
		}
		b.TokensIn += int64(e.TokensIn)
		b.TokensOut += int64(e.TokensOut)
		b.LatencyMS += e.LatencyMS
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan log: %w", err)
	}
	return buckets, lines, nil
}

func runCost(logPath, pricesPath string, jsonOut bool) error {
	book, err := loadPriceBook(pricesPath)
	if err != nil {
		return err
	}

	buckets, lines, err := scanCostBuckets(logPath)
	if err != nil {
		return err
	}

	rows := make([]*bucket, 0, len(buckets))
	var totUSD float64
	var totCalls int
	var totIn, totOut int64
	for _, b := range buckets {
		if p, ok := book.lookup(b.Model); ok {
			b.USD = (float64(b.TokensIn)*p.Input + float64(b.TokensOut)*p.Output) / 1_000_000
			totUSD += b.USD
		}
		totCalls += b.Calls
		totIn += b.TokensIn
		totOut += b.TokensOut
		rows = append(rows, b)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].USD != rows[j].USD {
			return rows[i].USD > rows[j].USD
		}
		if rows[i].TokensIn+rows[i].TokensOut != rows[j].TokensIn+rows[j].TokensOut {
			return rows[i].TokensIn+rows[i].TokensOut > rows[j].TokensIn+rows[j].TokensOut
		}
		if rows[i].Stage != rows[j].Stage {
			return rows[i].Stage < rows[j].Stage
		}
		return rows[i].Model < rows[j].Model
	})

	if jsonOut {
		out := struct {
			Lines  int       `json:"lines"`
			Calls  int       `json:"calls"`
			TokIn  int64     `json:"tokens_in_total"`
			TokOut int64     `json:"tokens_out_total"`
			USD    float64   `json:"usd_total,omitempty"`
			Rows   []*bucket `json:"rows"`
		}{lines, totCalls, totIn, totOut, totUSD, rows}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	hasUSD := book != nil
	printCostTable(rows, hasUSD)
	fmt.Println()
	fmt.Printf("lines=%d  calls=%d  tokens_in=%s  tokens_out=%s",
		lines, totCalls, fmtInt(totIn), fmtInt(totOut))
	if hasUSD {
		fmt.Printf("  est_usd=$%.2f", totUSD)
	}
	fmt.Println()
	return nil
}

func printCostTable(rows []*bucket, hasUSD bool) {
	headers := []string{"STAGE", "MODEL", "CALLS", "ERR", "TOK_IN", "TOK_OUT", "AVG_MS"}
	if hasUSD {
		headers = append(headers, "USD")
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	data := make([][]string, 0, len(rows))
	for _, r := range rows {
		avg := int64(0)
		if r.Calls > 0 {
			avg = r.LatencyMS / int64(r.Calls)
		}
		row := []string{
			r.Stage, r.Model,
			fmt.Sprintf("%d", r.Calls),
			fmt.Sprintf("%d", r.Errors),
			fmtInt(r.TokensIn),
			fmtInt(r.TokensOut),
			fmt.Sprintf("%d", avg),
		}
		if hasUSD {
			row = append(row, fmt.Sprintf("$%.4f", r.USD))
		}
		for i, c := range row {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
		data = append(data, row)
	}
	// header
	printRow(headers, widths)
	printRow(dashes(widths), widths)
	for _, row := range data {
		printRow(row, widths)
	}
}

func printRow(cells []string, widths []int) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		parts[i] = padRight(c, widths[i])
	}
	fmt.Println(strings.Join(parts, "  "))
}

func dashes(widths []int) []string {
	out := make([]string, len(widths))
	for i, w := range widths {
		out[i] = strings.Repeat("-", w)
	}
	return out
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func fmtInt(v int64) string {
	s := fmt.Sprintf("%d", v)
	// add thousands separators
	if v < 1000 && v > -1000 {
		return s
	}
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var out []byte
	for i, ch := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, ch)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
