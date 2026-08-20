# Credential Auditor

Evidence-driven credential hygiene for Git repositories.

Credential Auditor is an open-source Go CLI focused on a bounded question:

> What repository content and reachable history were actually inspected, which credential classes were checked, what evidence supports the result, and what still remains unknown?

The goal is **not** to claim perfect secret detection. The goal is to produce reproducible, safely redacted evidence about the checks that actually ran.

## Evidence pipeline

```text
working tree + staged files + local refs + reachable Git objects
                         ↓
                   detector registry
                         ↓
              redacted findings/evidence
                         ↓
       JSON report + operator report + digest
                         ↓
            PASS | FINDINGS | INDETERMINATE
                         ↓
          optional fail-closed CI publication gate
```

## V0 — local Git evidence CLI

V0 proves:

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

## V0.2 — CI / pre-publication gate

V0.2 adds an operator-facing evidence layer and a reusable publication-gate pattern without changing the bounded detector claim.

It adds:

- deterministic `--operator-out` text derived only from the already-redacted JSON report;
- report SHA-256 printed in the operator summary to bind human and machine evidence;
- fail-closed CI semantics: only `PASS` exits 0;
- full selected-history checkout guidance with `fetch-depth: 0` and tags;
- `persist-credentials: false` and read-only GitHub workflow permissions;
- pinned GitHub Actions template;
- a self-audit gate on Credential Auditor's own repository;
- CI proof that the operator and JSON reports never contain the synthetic matched value;
- optional redacted-report artifact retention; source/content upload to a hosted scanner is not required.

```bash
go build -trimpath -o credential-auditor ./cmd/credential-auditor
./credential-auditor \
  --repo /path/to/repository \
  --out audit-report.json \
  --operator-out audit-report.txt
```

See [`docs/CI_GATE_V02.md`](docs/CI_GATE_V02.md) and the pinned example in [`examples/github-actions/credential-audit.yml`](examples/github-actions/credential-audit.yml).

## Exit semantics

- `0` — `PASS`: the declared scan completed and no configured detector matched;
- `2` — `FINDINGS`: stop publication and investigate;
- `3` — `INDETERMINATE` or evidence/runtime failure: stop publication because coverage could not be completed safely.

Do not convert exits 2 or 3 to success in a publication gate.

## Report model

The JSON report records:

- HEAD identity when available;
- all refs observed locally;
- configured detector IDs;
- working/staged file counts;
- reachable object/blob counts;
- redacted finding locations with detector, scope, path, object ID and line when available;
- explicit coverage errors;
- claim boundary;
- deterministic report SHA-256.

The operator report records the same bounded state in review-friendly text. Matched secret values are intentionally absent from both outputs.

## Claim boundary

Credential Auditor does **not** prove:

- mathematical absence of secrets;
- validity or liveness of a detected credential;
- remote-ref coverage for refs that were never fetched locally;
- files/blobs above the declared 2 MiB V0 bound;
- full SAST or repository security;
- superiority to or replacement of GitHub Secret Scanning/Push Protection, Gitleaks or TruffleHog;
- production readiness.

`fetch-depth: 0` prevents a shallow selected-history scan, but it does not prove every remote-only ref from every hosting system was fetched. If your release policy requires additional refs, fetch them explicitly and treat that fetch policy as part of the evidence contract.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for Git coverage semantics, size limits and the performance boundary. The staged roadmap is tracked in issue #1.

## Development

```bash
gofmt -w .
go vet ./...
go test ./... -count=1
go build ./cmd/credential-auditor
```

CI proves the repository self-gate plus clean, historical-only and incomplete-scope controls and uploads only redacted evidence outputs.

## Security

See [`SECURITY.md`](SECURITY.md), especially the incident-response distinction between deleting a leaked value and rotating/revoking the credential.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New detectors require synthetic controls, redaction evidence and explicit limitations.

## Licence

Apache-2.0.
