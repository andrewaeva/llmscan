// Command llmscan is the CLI entrypoint for the LLM-based multi-agent code security scanner.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.3.0"

func main() {
	root := &cobra.Command{
		Use:           "llmscan",
		Short:         "LLM-based multi-agent code security scanner",
		Long:          "llmscan inspects a codebase with a hierarchy of specialized LLM agents: Orchestrator -> Scanner agents (DAG) -> Verifier -> FP-filter. v3 adds watchlist pre-filter, secrets pre-filter, taint analysis, reachability, structured JSON output, sqlite cache, baseline/diff mode, IaC scanners, voting, and evaluation harness.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(initConfigCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(harnessCmd())
	root.AddCommand(evalCmd())
	root.AddCommand(benchCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("llmscan", version)
		},
	}
}
