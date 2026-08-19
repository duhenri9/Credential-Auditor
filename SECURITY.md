# Security policy

Credential Auditor is designed to inspect material that may contain sensitive credentials. Its own reporting path therefore follows a strict rule: **identify the finding without echoing the matched secret value**.

## Reporting a vulnerability

Use GitHub private vulnerability reporting when available. Do not publish live tokens, private keys, repository contents or exploitable third-party details in a public issue.

If private reporting is unavailable, open a minimal issue requesting a private contact path without sensitive data.

## If the auditor finds a real credential

Treat deletion and revocation as different actions:

1. rotate or revoke the credential first;
2. determine whether the credential exists in reachable history, branches or tags;
3. review CI artifacts, logs, caches and mirrors that may also contain it;
4. rewrite/purge history only as part of the response plan, not as a substitute for revocation;
5. re-run provider-native and independent scanning controls where appropriate.

## V0 boundary

- local Git worktrees only;
- no repository content upload;
- no telemetry;
- matched values are not included in findings;
- blobs/files above the declared V0 size bound make the result indeterminate instead of being silently ignored;
- detector coverage is heuristic and incomplete by design.

A `PASS` report is not proof that no secret exists and does not replace GitHub Secret Scanning, Push Protection, Gitleaks, TruffleHog, provider revocation checks or a broader security review.
