# Contributing

Credential Auditor welcomes small, testable improvements to repository coverage, detector quality, redaction and evidence reporting.

## Before opening a PR

Run:

```bash
gofmt -w .
go vet ./...
go test ./... -count=1
go build ./cmd/credential-auditor
```

## Detector contributions

A new detector should include:

- a narrow description of what shape/class it detects;
- synthetic positive and negative fixtures;
- no live credential values;
- redaction tests proving the matched value is absent from reports;
- explicit false-positive/false-negative limitations.

Do not describe a heuristic detector as proof that a credential is valid or active.

## Coverage changes

If a change adds or removes a Git scope, update the report contract and add a control that fails when that scope is unavailable. Silent skips are not acceptable for a `PASS` claim.

## Performance changes

Optimisations such as `git cat-file --batch` should preserve object/ref coverage evidence and deterministic report semantics. Include benchmarks only when methodology and fixture size are documented.
