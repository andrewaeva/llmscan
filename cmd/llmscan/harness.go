package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/andrewaeva/llmscan/internal/report"
)

func harnessCmd() *cobra.Command {
	var (
		out, id, name, image, target, cfg, failOn string
	)
	cmd := &cobra.Command{
		Use:   "harness-step",
		Short: "Emit a Harness CI/STO pipeline step that runs llmscan and ingests SARIF",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := os.Stdout
			if out != "" {
				fh, err := os.Create(out)
				if err != nil {
					return err
				}
				defer fh.Close()
				w = fh
			}
			return report.WriteHarnessStepYAML(w, report.HarnessStepOptions{
				Identifier: id, Name: name, Image: image,
				TargetPath: target, ConfigPath: cfg, FailOn: failOn,
			})
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVar(&id, "id", "llmscan_sast", "Harness step identifier")
	cmd.Flags().StringVar(&name, "name", "LLM SAST", "Display name")
	cmd.Flags().StringVar(&image, "image", "ghcr.io/andrewaeva/llmscan:latest", "Container image with llmscan")
	cmd.Flags().StringVar(&target, "target", ".", "Target path inside the workspace")
	cmd.Flags().StringVar(&cfg, "config", "", "Optional llmscan.yaml path inside the container")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Severity threshold for failing the pipeline")
	return cmd
}
