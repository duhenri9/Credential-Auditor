package audit

import (
	"strings"
	"testing"
)

func TestRenderOperatorReportIsDeterministicAndRedacted(t *testing.T) {
	report := Report{
		Outcome:       Findings,
		Head:          "abc123",
		Refs:          []string{"refs/tags/v1", "refs/heads/main"},
		DetectorIDs:   []string{"private-key-header", "credential-auditor-fixture"},
		ReachableObjects: 9,
		ReachableBlobs:   4,
		Findings: []Finding{
			{DetectorID: "private-key-header", Scope: "reachable-history", Path: "keys/test.pem", ObjectID: "deadbeef", Line: 1},
			{DetectorID: "credential-auditor-fixture", Scope: "working-tree", Path: "fixture.txt", Line: 2},
		},
		ClaimBoundary: "bounded claim",
		ReportSHA256:  "feedface",
	}

	first := RenderOperatorReport(report)
	second := RenderOperatorReport(report)
	if first != second {
		t.Fatal("operator report must be deterministic")
	}
	for _, expected := range []string{
		"Outcome: FINDINGS",
		"Report SHA-256: feedface",
		"detector=private-key-header",
		"scope=reachable-history",
		"Claim boundary: bounded claim",
	} {
		if !strings.Contains(first, expected) {
			t.Fatalf("operator report missing %q", expected)
		}
	}
	if strings.Contains(first, "CA_TEST_SECRET_") {
		t.Fatal("operator report must not render synthetic secret values")
	}
}
