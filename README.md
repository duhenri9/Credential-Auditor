# Credential Auditor

Evidence-driven credential hygiene for Git repositories.

Credential Auditor is an open-source Go CLI focused on a bounded question:

> What repository content and reachable history were actually inspected, which credential classes were checked, what evidence supports the result, and what still remains unknown?

The goal is **not** to claim perfect secret detection. The goal is to produce reproducible, safely redacted evidence about the checks that actually ran.

## V0

```text
working tree + staged files + local refs + reachable Git objects
                         ↓
                   detector registry
                         ↓
              redacted findings/evidence
                         ↓
          coverage + deterministic report digest
                         ↓
            PASS | FINDINGS | INDETERMINATE
```

### What V0 proves

- canonicalisation to the containing Git worktree root;
- current tracked and untracked non-ignored file scanning;
- staged/index content scanning;
- enumeration of all refs currently present in the local repository;
- inspection of blobs reachable from those fetched/local refs;
- detection of a synthetic secret that exists only in historical Git data after deletion from HEAD;
- a small explicit detector registry;
- credential-shaped path evidence;
- no matched value stored in findings;
- explicit incomplete-scope behaviour;
- deterministic report SHA-256.

### What V0 does not prove

- mathematical absence of secrets;
- validity or liveness of a detected credential;
- remote-ref coverage for refs that were never fetched locally;
- files/blobs above the declared 2 MiB V0 bound;
- full SAST or repository security;
- superiority to or replacement of GitHub Secret Scanning, Push Protection, Gitleaks or TruffleHog;
- production readiness.

## Build and run

```bash
go build -trimpath -o credential-auditor ./cmd/credential-auditor
./credential-auditor --repo /path/to/repository --out audit-report.json
```

Exit codes:

- `0` — `PASS`;
- `2` — `FINDINGS`;
- `3` — `INDETERMINATE` or report/runtime failure.

## Report model

The JSON report records:

- HEAD identity when available;
- all refs observed locally;
- configured detector ids;
- working/staged file counts;
- reachable object/blob counts;
- redacted finding locations with detector, scope, path, object id and line when available;
- explicit coverage errors;
- claim boundary;
- deterministic report SHA-256.

Matched secret values are intentionally absent from the report.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for Git coverage semantics, size limits and the performance boundary. The staged roadmap is tracked in issue #1.

## Development

```bash
gofmt -w .
go vet ./...
go test ./... -count=1
go build ./cmd/credential-auditor
```

CI additionally builds real temporary Git repositories and proves clean, historical-only and incomplete-scope controls before uploading redacted evidence reports.

## Security

See [`SECURITY.md`](SECURITY.md), especially the incident-response distinction between deleting a leaked value and rotating/revoking the credential.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New detectors require synthetic controls, redaction evidence and explicit limitations.

## Licence

Apache-2.0.
