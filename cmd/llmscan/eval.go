package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/eval"
	"github.com/andrewaeva/llmscan/internal/pipeline"
)

func evalCmd() *cobra.Command {
	var (
		adapter, datasetPath, target, cfgPath, outPath, format string
		verbose                                                bool
	)
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Run llmscan against a labeled dataset and compute precision/recall/F1",
		Long: "eval loads ground-truth labels via a local adapter and runs the scanner against the target codebase. " +
			"Adapters: owasp-benchmark, securityeval, juliet, generic. No network downloads are performed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEval(adapter, datasetPath, target, cfgPath, outPath, format, verbose)
		},
	}
	cmd.Flags().StringVar(&adapter, "adapter", "", "Dataset adapter: owasp-benchmark | securityeval | juliet | generic")
	cmd.Flags().StringVar(&datasetPath, "dataset-path", "", "Local path to dataset (file or directory)")
	cmd.Flags().StringVar(&target, "target", "", "Codebase path to scan (usually the dataset code root)")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "Path to llmscan.yaml")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | json")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	return cmd
}

func runEval(adapter, datasetPath, target, cfgPath, outPath, format string, verbose bool) error {
	if adapter == "" || datasetPath == "" || target == "" {
		return fmt.Errorf("eval requires --adapter, --dataset-path, and --target")
	}
	labels, err := eval.LoadLabels(adapter, datasetPath)
	if err != nil {
		return fmt.Errorf("load labels: %w", err)
	}
	if len(labels) == 0 {
		return fmt.Errorf("dataset %q yielded zero labels", datasetPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	eng := pipeline.New(cfg)
	eng.Verbose = verbose
	rep, err := eng.Run(ctx, target)
	if err != nil {
		return err
	}
	metrics := eval.Compare(rep.Findings, labels)

	out, closeOut, err := openOutput(outPath)
	if err != nil {
		return err
	}
	defer func() { _ = closeOut() }()
	if strings.ToLower(format) == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(metrics)
	}
	eval.PrintReport(metrics)
	return nil
}
