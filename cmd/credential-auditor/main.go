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
	operatorOut := flag.String("operator-out", "", "optional human-readable operator report path")
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
		if err := writeEvidenceFile(*out, encoded); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write JSON report")
			os.Exit(3)
		}
	}

	if *operatorOut != "" {
		operator := []byte(audit.RenderOperatorReport(report))
		if err := writeEvidenceFile(*operatorOut, operator); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write operator report")
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

func writeEvidenceFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
