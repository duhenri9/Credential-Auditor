package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/duhenri9/Credential-Auditor/internal/audit"
)

func main() {
	repo := flag.String("repo", ".", "Git worktree to audit")
	out := flag.String("out", "", "optional JSON report path")
	timeout := flag.Duration("timeout", 30*time.Second, "overall audit timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := audit.AuditRepository(ctx, *repo)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to encode report")
		os.Exit(3)
	}
	encoded = append(encoded, '\n')

	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "failed to create report directory")
			os.Exit(3)
		}
		if err := os.WriteFile(*out, encoded, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write report")
			os.Exit(3)
		}
	}

	fmt.Print(string(encoded))
	switch report.Outcome {
	case audit.Pass:
		os.Exit(0)
	case audit.Findings:
		os.Exit(2)
	default:
		os.Exit(3)
	}
}
