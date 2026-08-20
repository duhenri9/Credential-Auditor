package audit

import (
	"fmt"
	"sort"
	"strings"
)

// RenderOperatorReport converts the redacted machine report into a deterministic
// human-readable summary. It never receives or renders matched secret values.
func RenderOperatorReport(report Report) string {
	var b strings.Builder

	fmt.Fprintln(&b, "Credential Auditor evidence report")
	fmt.Fprintf(&b, "Outcome: %s\n", report.Outcome)
	fmt.Fprintf(&b, "Report SHA-256: %s\n", report.ReportSHA256)
	fmt.Fprintf(&b, "HEAD: %s\n", emptyAsUnknown(report.Head))
	fmt.Fprintf(&b, "Working files scanned: %d\n", report.WorkingFilesScanned)
	fmt.Fprintf(&b, "Staged files scanned: %d\n", report.StagedFilesScanned)
	fmt.Fprintf(&b, "Reachable objects: %d\n", report.ReachableObjects)
	fmt.Fprintf(&b, "Reachable blobs: %d\n", report.ReachableBlobs)
	fmt.Fprintf(&b, "Configured detectors: %d\n", len(report.DetectorIDs))
	fmt.Fprintf(&b, "Refs observed: %d\n", len(report.Refs))
	fmt.Fprintf(&b, "Findings: %d\n", len(report.Findings))
	fmt.Fprintf(&b, "Errors: %d\n", len(report.Errors))

	if len(report.Findings) > 0 {
		fmt.Fprintln(&b, "")
		fmt.Fprintln(&b, "Findings (secret values are never rendered):")
		findings := append([]Finding(nil), report.Findings...)
		sort.Slice(findings, func(i, j int) bool {
			left := findings[i]
			right := findings[j]
			if left.Scope != right.Scope {
				return left.Scope < right.Scope
			}
			if left.Path != right.Path {
				return left.Path < right.Path
			}
			if left.Line != right.Line {
				return left.Line < right.Line
			}
			return left.DetectorID < right.DetectorID
		})
		for _, finding := range findings {
			line := ""
			if finding.Line > 0 {
				line = fmt.Sprintf(":%d", finding.Line)
			}
			object := ""
			if finding.ObjectID != "" {
				object = " object=" + finding.ObjectID
			}
			fmt.Fprintf(
				&b,
				"- detector=%s scope=%s path=%s%s%s\n",
				finding.DetectorID,
				finding.Scope,
				finding.Path,
				line,
				object,
			)
		}
	}

	if len(report.Errors) > 0 {
		fmt.Fprintln(&b, "")
		fmt.Fprintln(&b, "Coverage errors:")
		errors := append([]string(nil), report.Errors...)
		sort.Strings(errors)
		for _, item := range errors {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}

	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "Claim boundary: %s\n", report.ClaimBoundary)
	return b.String()
}

func emptyAsUnknown(value string) string {
	if value == "" {
		return "[unavailable]"
	}
	return value
}
