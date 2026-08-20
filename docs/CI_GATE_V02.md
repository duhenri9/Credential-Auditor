# CI / pre-publication gate V0.2

Credential Auditor V0.2 turns the local evidence CLI into a fail-closed pre-publication control without requiring source upload to a third-party scanning service.

## Gate contract

A CI job should:

1. checkout the repository with full selected history (`fetch-depth: 0`) and tags;
2. keep checkout credentials non-persistent;
3. build the auditor from a pinned/reviewed source revision;
4. audit the local worktree, staged state and every Git object/ref that is actually present in that checkout;
5. retain both the deterministic JSON report and the human-readable operator report;
6. fail on `FINDINGS` (exit 2) and `INDETERMINATE` (exit 3);
7. continue only on `PASS` (exit 0).

`PASS` is deliberately bounded by the history/refs actually present locally. `fetch-depth: 0` prevents shallow selected-history scans, but it does not magically prove that every remote-only ref from every hosting system was fetched. If your publication policy requires additional refs, fetch them explicitly before running the auditor and record that policy alongside the evidence.

## Evidence outputs

`--out` writes `credential-auditor.report.v0` JSON with:

- exact HEAD;
- observed refs;
- configured detector IDs;
- working/staged/reachable-object coverage counts;
- redacted finding metadata only;
- coverage errors;
- explicit claim boundary;
- deterministic report SHA-256.

`--operator-out` writes a deterministic text summary derived only from that redacted report. It never receives or displays the matched credential value.

The operator report includes the JSON report digest so a reviewer can bind the human-readable summary to the machine-readable evidence.

## Fail-closed exit semantics

| Exit | Outcome | CI meaning |
| --- | --- | --- |
| `0` | `PASS` | declared scan completed; no configured detector matched |
| `2` | `FINDINGS` | stop publication; inspect redacted finding metadata and rotate/revoke real credentials first |
| `3` | `INDETERMINATE` | stop publication; required scan coverage could not be completed safely |

Do not convert exit 2 or 3 to success in a publication gate.

## GitHub Actions template

See [`../examples/github-actions/credential-audit.yml`](../examples/github-actions/credential-audit.yml).

The template pins checkout/setup actions, uses `contents: read`, sets `persist-credentials: false`, fetches full selected history and tags, and runs the scanner locally. Uploading the redacted reports is optional and should follow the repository's evidence-retention policy.

## Privacy boundary

Credential Auditor does not require telemetry and does not need repository/source content uploaded to a hosted scanner. The CLI invokes local Git and reads local files/objects. Reports intentionally contain detector IDs, scopes, paths, object IDs and line numbers — never the matched value.

The report may still contain repository metadata that an organisation treats as sensitive, so artifact retention/access should be configured deliberately.

## Incident response

When a real credential is detected:

1. rotate/revoke it first;
2. determine which branches/tags/commits/artifacts/logs/caches may contain it;
3. then decide whether history/ref cleanup is required;
4. re-run the declared scan after remediation.

Deleting a file or rewriting Git history is not credential revocation.

## Claim boundary

V0.2 is not proof that no credential exists. Detection remains limited to configured detectors, credential-shaped paths, local readable content size limits and the Git history/refs actually available to the process. It is complementary to GitHub Secret Scanning/Push Protection, Gitleaks, TruffleHog and other specialised scanners.
