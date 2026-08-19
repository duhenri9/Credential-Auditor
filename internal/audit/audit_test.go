package audit

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureSecret = "CA_TEST_SECRET_" + "ABCDEFGHIJKLMNOP"

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	all := append([]string{"-C", root}, args...)
	cmd := exec.Command("git", all...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func repo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.email", "fixture@example.invalid")
	runGit(t, root, "config", "user.name", "Credential Auditor Fixture")
	write(t, root, "README.md", "clean fixture\n")
	runGit(t, root, "add", "README.md")
	runGit(t, root, "commit", "-m", "initial")
	return root
}

func hasFinding(report Report, scope, detectorID string) bool {
	for _, finding := range report.Findings {
		if finding.Scope == scope && finding.DetectorID == detectorID {
			return true
		}
	}
	return false
}

func TestCleanRepositoryPasses(t *testing.T) {
	report := AuditRepository(context.Background(), repo(t))
	if report.Outcome != Pass {
		t.Fatalf("expected PASS, got %s with errors=%v findings=%v", report.Outcome, report.Errors, report.Findings)
	}
	if report.ReachableBlobs == 0 || report.ReachableObjects == 0 {
		t.Fatal("expected reachable-history coverage evidence")
	}
}

func TestCurrentTreeSyntheticSecretIsFoundWithoutEchoingValue(t *testing.T) {
	root := repo(t)
	write(t, root, "local-config.txt", "fixture="+fixtureSecret+"\n")
	report := AuditRepository(context.Background(), root)
	if report.Outcome != Findings {
		t.Fatalf("expected FINDINGS, got %s", report.Outcome)
	}
	if !hasFinding(report, "working-tree", "credential-auditor-fixture") {
		t.Fatal("expected working-tree fixture detector finding")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), fixtureSecret) {
		t.Fatal("report must not echo matched secret value")
	}
}

func TestStagedSyntheticSecretIsCovered(t *testing.T) {
	root := repo(t)
	write(t, root, "staged.txt", "fixture="+fixtureSecret+"\n")
	runGit(t, root, "add", "staged.txt")
	report := AuditRepository(context.Background(), root)
	if report.Outcome != Findings {
		t.Fatalf("expected FINDINGS, got %s", report.Outcome)
	}
	if !hasFinding(report, "staged", "credential-auditor-fixture") {
		t.Fatal("expected staged fixture detector finding")
	}
}

func TestHistoricalOnlySecretIsFoundAfterDeletionFromHead(t *testing.T) {
	root := repo(t)
	write(t, root, "historical.txt", "fixture="+fixtureSecret+"\n")
	runGit(t, root, "add", "historical.txt")
	runGit(t, root, "commit", "-m", "add historical fixture")
	if err := os.Remove(filepath.Join(root, "historical.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "-u")
	runGit(t, root, "commit", "-m", "remove historical fixture")

	report := AuditRepository(context.Background(), root)
	if report.Outcome != Findings {
		t.Fatalf("expected FINDINGS, got %s", report.Outcome)
	}
	if !hasFinding(report, "reachable-history", "credential-auditor-fixture") {
		t.Fatal("expected historical-only fixture detector finding")
	}
	if hasFinding(report, "working-tree", "credential-auditor-fixture") {
		t.Fatal("historical-only secret must not exist in current working tree")
	}
}

func TestNonRepositoryIsIndeterminate(t *testing.T) {
	report := AuditRepository(context.Background(), t.TempDir())
	if report.Outcome != Indeterminate {
		t.Fatalf("expected INDETERMINATE, got %s", report.Outcome)
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected explicit coverage error")
	}
}

func TestReportDigestIsDeterministicForStableRepository(t *testing.T) {
	root := repo(t)
	first := AuditRepository(context.Background(), root)
	second := AuditRepository(context.Background(), root)
	if first.ReportSHA256 != second.ReportSHA256 {
		t.Fatalf("expected stable digest: %s != %s", first.ReportSHA256, second.ReportSHA256)
	}
}
