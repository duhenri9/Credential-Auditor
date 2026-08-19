package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxBlobBytes = 2 * 1024 * 1024

const ClaimBoundary = "PASS means only that the declared repository scopes were scanned with the configured V0 detectors and no configured match was found. It is not proof that no secret exists."

type Outcome string

const (
	Pass          Outcome = "PASS"
	Findings      Outcome = "FINDINGS"
	Indeterminate Outcome = "INDETERMINATE"
)

type detector struct {
	id      string
	pattern *regexp.Regexp
}

var detectors = []detector{
	{id: "credential-auditor-fixture", pattern: regexp.MustCompile(`CA_TEST_SECRET_[A-Z0-9]{16}`)},
	{id: "github-token-shape", pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`)},
	{id: "aws-access-key-shape", pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{id: "private-key-header", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
}

type Finding struct {
	DetectorID string `json:"detector_id"`
	Scope      string `json:"scope"`
	Path       string `json:"path"`
	ObjectID   string `json:"object_id,omitempty"`
	Line       int    `json:"line,omitempty"`
}

type Report struct {
	Schema              string    `json:"schema"`
	Outcome             Outcome   `json:"outcome"`
	Head                string    `json:"head"`
	Refs                []string  `json:"refs"`
	DetectorIDs         []string  `json:"detector_ids"`
	WorkingFilesScanned int       `json:"working_files_scanned"`
	StagedFilesScanned  int       `json:"staged_files_scanned"`
	ReachableObjects    int       `json:"reachable_objects"`
	ReachableBlobs      int       `json:"reachable_blobs"`
	Findings            []Finding `json:"findings"`
	Errors              []string  `json:"errors"`
	ClaimBoundary       string    `json:"claim_boundary"`
	ReportSHA256        string    `json:"report_sha256"`
}

func git(ctx context.Context, root string, args ...string) ([]byte, error) {
	all := append([]string{"-C", root}, args...)
	cmd := exec.CommandContext(ctx, "git", all...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func splitNUL(data []byte) []string {
	parts := bytes.Split(data, []byte{0})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, string(part))
		}
	}
	return result
}

func detectorIDs() []string {
	ids := make([]string, 0, len(detectors)+1)
	for _, item := range detectors {
		ids = append(ids, item.id)
	}
	ids = append(ids, "credential-shaped-path")
	sort.Strings(ids)
	return ids
}

func credentialShapedPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".env.example" || base == ".env.sample" {
		return false
	}
	if base == ".env" || base == ".npmrc" || base == ".pypirc" {
		return true
	}
	if base == "id_rsa" || base == "id_ed25519" {
		return true
	}
	return strings.Contains(base, "credentials")
}

func scanContent(scope, path, objectID string, data []byte) []Finding {
	result := make([]Finding, 0)
	for _, item := range detectors {
		locations := item.pattern.FindAllIndex(data, -1)
		for _, location := range locations {
			line := bytes.Count(data[:location[0]], []byte{'\n'}) + 1
			result = append(result, Finding{
				DetectorID: item.id,
				Scope:      scope,
				Path:       filepath.ToSlash(path),
				ObjectID:   objectID,
				Line:       line,
			})
		}
	}
	return result
}

func appendError(errors []string, format string, args ...any) []string {
	return append(errors, fmt.Sprintf(format, args...))
}

func scanWorkingTree(ctx context.Context, root string, report *Report) {
	output, err := git(ctx, root, "ls-files", "-co", "--exclude-standard", "-z")
	if err != nil {
		report.Errors = appendError(report.Errors, "working-tree enumeration failed")
		return
	}

	for _, path := range splitNUL(output) {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		info, statErr := os.Stat(fullPath)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > maxBlobBytes {
			report.Errors = appendError(report.Errors, "working-tree file exceeds V0 size limit: %s", path)
			continue
		}
		data, readErr := os.ReadFile(fullPath)
		if readErr != nil {
			report.Errors = appendError(report.Errors, "working-tree read failed: %s", path)
			continue
		}
		report.WorkingFilesScanned++
		report.Findings = append(report.Findings, scanContent("working-tree", path, "", data)...)
		if credentialShapedPath(path) {
			report.Findings = append(report.Findings, Finding{DetectorID: "credential-shaped-path", Scope: "working-tree-path", Path: filepath.ToSlash(path)})
		}
	}
}

func scanStaged(ctx context.Context, root string, report *Report) {
	output, err := git(ctx, root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		report.Errors = appendError(report.Errors, "staged enumeration failed")
		return
	}

	for _, path := range splitNUL(output) {
		data, showErr := git(ctx, root, "show", ":"+path)
		if showErr != nil {
			report.Errors = appendError(report.Errors, "staged content read failed: %s", path)
			continue
		}
		if len(data) > maxBlobBytes {
			report.Errors = appendError(report.Errors, "staged file exceeds V0 size limit: %s", path)
			continue
		}
		report.StagedFilesScanned++
		report.Findings = append(report.Findings, scanContent("staged", path, "", data)...)
	}
}

func scanRefs(ctx context.Context, root string, report *Report) {
	output, err := git(ctx, root, "for-each-ref", "--format=%(refname)")
	if err != nil {
		report.Errors = appendError(report.Errors, "ref enumeration failed")
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			report.Refs = append(report.Refs, line)
		}
	}
	sort.Strings(report.Refs)
}

func scanHistory(ctx context.Context, root string, report *Report) {
	output, err := git(ctx, root, "rev-list", "--objects", "--all")
	if err != nil {
		report.Errors = appendError(report.Errors, "reachable-history enumeration failed")
		return
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		objectID := parts[0]
		if seen[objectID] {
			continue
		}
		seen[objectID] = true
		report.ReachableObjects++

		typeOutput, typeErr := git(ctx, root, "cat-file", "-t", objectID)
		if typeErr != nil {
			report.Errors = appendError(report.Errors, "object type unavailable: %s", objectID)
			continue
		}
		if strings.TrimSpace(string(typeOutput)) != "blob" {
			continue
		}

		sizeOutput, sizeErr := git(ctx, root, "cat-file", "-s", objectID)
		if sizeErr != nil {
			report.Errors = appendError(report.Errors, "blob size unavailable: %s", objectID)
			continue
		}
		size, parseErr := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)
		if parseErr != nil {
			report.Errors = appendError(report.Errors, "blob size invalid: %s", objectID)
			continue
		}
		if size > maxBlobBytes {
			report.Errors = appendError(report.Errors, "reachable blob exceeds V0 size limit: %s", objectID)
			continue
		}

		data, blobErr := git(ctx, root, "cat-file", "blob", objectID)
		if blobErr != nil {
			report.Errors = appendError(report.Errors, "reachable blob read failed: %s", objectID)
			continue
		}
		report.ReachableBlobs++
		path := "[unknown-path]"
		if len(parts) == 2 {
			path = parts[1]
		}
		report.Findings = append(report.Findings, scanContent("reachable-history", path, objectID, data)...)
	}
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.ObjectID != b.ObjectID {
			return a.ObjectID < b.ObjectID
		}
		if a.DetectorID != b.DetectorID {
			return a.DetectorID < b.DetectorID
		}
		return a.Line < b.Line
	})
}

func digestReport(report Report) string {
	report.ReportSHA256 = ""
	encoded, _ := json.Marshal(report)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func indeterminateReport(report Report, reason string) Report {
	report.Outcome = Indeterminate
	report.Errors = append(report.Errors, reason)
	report.ReportSHA256 = digestReport(report)
	return report
}

func AuditRepository(ctx context.Context, root string) Report {
	report := Report{
		Schema:        "credential-auditor.report.v0",
		Head:          "UNBORN",
		Refs:          []string{},
		DetectorIDs:   detectorIDs(),
		Findings:      []Finding{},
		Errors:        []string{},
		ClaimBoundary: ClaimBoundary,
	}

	inside, err := git(ctx, root, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(string(inside)) != "true" {
		return indeterminateReport(report, "path is not an accessible Git worktree")
	}

	topLevel, topErr := git(ctx, root, "rev-parse", "--show-toplevel")
	if topErr != nil {
		return indeterminateReport(report, "repository top-level path could not be resolved")
	}
	root = strings.TrimSpace(string(topLevel))
	if root == "" {
		return indeterminateReport(report, "repository top-level path is empty")
	}

	if head, headErr := git(ctx, root, "rev-parse", "HEAD"); headErr == nil {
		report.Head = strings.TrimSpace(string(head))
	}

	scanRefs(ctx, root, &report)
	scanWorkingTree(ctx, root, &report)
	scanStaged(ctx, root, &report)
	scanHistory(ctx, root, &report)

	sort.Strings(report.Errors)
	sortFindings(report.Findings)
	if len(report.Errors) > 0 {
		report.Outcome = Indeterminate
	} else if len(report.Findings) > 0 {
		report.Outcome = Findings
	} else {
		report.Outcome = Pass
	}
	report.ReportSHA256 = digestReport(report)
	return report
}
