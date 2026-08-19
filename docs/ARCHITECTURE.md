# Credential Auditor V0 architecture

Credential Auditor treats **scan coverage** as evidence, not as an implied guarantee.

```text
Git worktree
   ├─ current tracked + untracked non-ignored files
   ├─ staged content
   ├─ local branches/tags
   └─ objects reachable from fetched refs
              ↓
        detector registry
              ↓
 redacted findings + coverage counts
              ↓
 PASS | FINDINGS | INDETERMINATE
              ↓
 deterministic report digest
```

## Repository scope

V0 asks Git directly for:

- current tracked/untracked non-ignored paths via `git ls-files`;
- staged paths and index content;
- local `refs/heads/*` and `refs/tags/*`;
- objects reachable from `git rev-list --objects --all`.

For each reachable object V0 checks its type and scans reachable blobs. A blob deleted from the current tree can therefore still produce a historical finding.

The report records the refs and object/blob counts it actually saw. It does **not** claim to cover remote refs that were never fetched into the local repository.

## Detector model

V0 deliberately starts small:

- a safe synthetic fixture detector used for deterministic controls;
- GitHub token shape;
- AWS access-key shape;
- private-key headers;
- credential-shaped tracked paths.

A finding stores detector id, scope, path, object id and line when available. It never stores the matched value.

The synthetic detector exists to prove scanner mechanics without putting live credentials in public fixtures.

## Result semantics

- `PASS`: every declared V0 scan phase completed and no configured detector matched.
- `FINDINGS`: scan coverage completed and at least one configured detector matched.
- `INDETERMINATE`: required coverage could not be completed safely, including V0 size-limit skips or an inaccessible/non-Git path.

An indeterminate report can still contain useful findings; the state means a complete PASS claim is unavailable.

## Size/resource boundary

V0 refuses to claim full coverage when an individual working file, staged file or reachable blob exceeds 2 MiB. This is an explicit engineering bound, not a silent skip.

The first implementation uses Git subprocesses per reachable object for simple, inspectable correctness. A future performance gate may move to long-lived `git cat-file --batch` plumbing, but no throughput claim should be made until that implementation has benchmarks and regression tests.

## Report integrity

The deterministic SHA-256 covers the redacted report payload. It identifies the evidence record; it is not a signature and does not prove that the underlying Git repository has not changed after the audit.
