package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// benchCmd wraps `go test -bench` so users can run llmscan's microbenchmarks
// without remembering the exact Go invocation. It targets internal packages by
// default and forwards extra flags after `--` straight to `go test`.
func benchCmd() *cobra.Command {
	var (
		pattern   string
		benchtime string
		count     int
		mem       bool
		cpuprof   string
		memprof   string
		pkg       string
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "bench [-- extra go test flags]",
		Short: "Run the built-in Go benchmarks for llmscan packages",
		Long: `Runs the unit-level Go benchmarks shipped with llmscan
(internal/secrets, watchlist, voting, baseline, chunker, cache, taint, ...).
Equivalent to:
  go test -run=^$ -bench=<pattern> -benchtime=<duration> [-benchmem] <pkg>

Anything after a literal "--" is passed verbatim to "go test", e.g.:
  llmscan bench -- -count=3 -timeout=300s`,
		RunE: func(c *cobra.Command, args []string) error {
			gotestArgs := []string{
				"test",
				"-run=^$",
				"-bench=" + pattern,
				"-benchtime=" + benchtime,
				fmt.Sprintf("-count=%d", count),
			}
			if mem {
				gotestArgs = append(gotestArgs, "-benchmem")
			}
			if cpuprof != "" {
				gotestArgs = append(gotestArgs, "-cpuprofile="+cpuprof)
			}
			if memprof != "" {
				gotestArgs = append(gotestArgs, "-memprofile="+memprof)
			}
			if verbose {
				gotestArgs = append(gotestArgs, "-v")
			}
			gotestArgs = append(gotestArgs, pkg)
			gotestArgs = append(gotestArgs, args...)

			fmt.Fprintln(os.Stderr, "+ go", join(gotestArgs))
			run := exec.Command("go", gotestArgs...)
			run.Stdout = os.Stdout
			run.Stderr = os.Stderr
			run.Env = os.Environ()
			return run.Run()
		},
	}
	cmd.Flags().StringVarP(&pattern, "pattern", "p", ".", "Benchmark name pattern (passed to -bench)")
	cmd.Flags().StringVar(&benchtime, "benchtime", "2x", "-benchtime value (e.g. 2x, 5s, 200ms)")
	cmd.Flags().IntVar(&count, "count", 1, "-count value (number of times each benchmark is run)")
	cmd.Flags().BoolVar(&mem, "mem", true, "Include allocation stats (-benchmem)")
	cmd.Flags().StringVar(&cpuprof, "cpuprofile", "", "Write CPU profile to file")
	cmd.Flags().StringVar(&memprof, "memprofile", "", "Write memory profile to file")
	cmd.Flags().StringVar(&pkg, "pkg", "./internal/...", "Go packages to benchmark")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose go test output")
	return cmd
}

func join(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
