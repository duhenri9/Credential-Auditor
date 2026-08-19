# Credential Auditor

Evidence-driven credential hygiene for Git repositories.

Credential Auditor is an open-source CLI project focused on a bounded question:

> What repository content and reachable history were actually inspected, which credential classes were checked, what evidence supports the result, and what still remains unknown?

The goal is not to claim perfect secret detection. The goal is to produce reproducible, safely redacted evidence about the checks that were actually performed.

## Status

Early public foundation. V0 is being built around synthetic repositories with current-tree, historical-secret and clean negative/positive controls.

## Design principles

- Never equate heuristic scanning with proof of absence.
- Scan evidence must describe exact scope and coverage.
- Secret values must not be echoed into reports.
- Reachable history matters, not only the current working tree.
- Failure and indeterminate states are explicit.
- The core path remains local-first and telemetry-free.

## V0 target

```text
working tree + staged files + reachable history + refs
                    ↓
              detector registry
                    ↓
           redacted findings/evidence
                    ↓
     coverage + deterministic report digest
                    ↓
       PASS | FINDINGS | INDETERMINATE
```

This project is not intended to replace GitHub Secret Scanning, Push Protection, Gitleaks, TruffleHog or a full SAST platform. Its differentiator is evidence quality, bounded claims and reproducible repository-coverage reporting.

## Licence

Apache-2.0 planned for the public V0. Licence file will be added with the first implementation PR.
