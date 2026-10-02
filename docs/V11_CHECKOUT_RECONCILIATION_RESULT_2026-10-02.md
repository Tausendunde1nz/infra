# V11 read-only checkout reconciliation result — 2026-10-02

Source: `9d1f4f8cce7da50ad430313a6a0c8f4e9f08f98a`.
One authorized read-only sudo run, completed with exit 2. No repeat privileged run.
Final classification: **LOCAL_CHECKOUT_DRIFT**. V11 remains **LIVE_NO_GO**.

## What is proven

The detached local HEAD is exactly `b78bb2a753aa815d47a99969668d64960573050b`.
Commit payload and tree `5135053083ceb2e669e5932cf0ff61b3d24dab9d` match the trusted
GitHub Control PR #65. `9b383960291da469671c3888cfa4fdcc3c33cf01` is an ancestor.
The copied index exactly matches that tree. All **186 tracked entries** match their
Git blob content and executable/symlink type expectations. There is no tracked content
or index-tree drift. No Git locks, active writers/CWD processes, incomplete process
visibility, or concurrent metadata/worktree change were reported during the check.
These are snapshot observations, not proof that a future writer cannot appear.
The check itself took approximately 2.49 monotonic seconds after bootstrap/authentication.

Index: root:chatops 0600, one link, inode 1460562, SHA-256
`8b8771f04211ebdf351f306559a7ee6a5e538bc68a078917552da6c5cc81d49c`.
Tracked-worktree manifest SHA-256:
`1c1260933d12c00f075b8cd3db668692e94a83dc01fb3adcea3b9e5592e4e38d`.
No configured external diff/textconv/hook/fsmonitor feature was found. Source Git
configuration was never executed; the verifier used its isolated configuration.

## Concrete remaining differences — no cleanup authorization

**99 untracked entries**, including ignored files, are present. The exact relative
paths are recorded in the adjacent JSON; prefix all with `/opt/tu1nz_repos/control/`.
Counts: 13 root files, 23 analysis files, 23 test cache files, 14 rebaseline files,
1 nginx path, 9 script/cache files, 14 legacy unit files and 2 systemd files.
Examples include `.r28r4-control-payload-clean.tar.gz`, generated checksum/reference
files, `scripts/encrypted_drive_backup`, historical incident records, Python caches,
and `systemd/tu1nz-git-sync.{service,timer}`. Their contents were NOT read or copied.
No inference of maliciousness, recent creation or live execution follows from their
names. The historical `.token_rotation.lock` path is an untracked filename, not a
finding of an active Git lock or token transaction.

Untracked files make the current strict complete-checkout attestation fail. This does
not contradict the byte-clean tracked tree. Do not delete/archive/move these entries,
run git clean, widen ignore rules, or introduce a blanket allowlist merely to pass.
Only an explicit narrowly reviewed ownership/content contract can distinguish permitted
local evidence/runtime artifacts from genuine unwanted extras.

Ownership remains mixed: checkout chatops:chatops 2770; .git chatops:chatops 2775;
index root:chatops 0600; no POSIX ACL xattrs on these reported paths. A root-owned
index in a chatops-writable parent is not a privileged-only publishing boundary.
The read-only root report solves index readability for attestation, but does not prove
that this ownership model is intentional or safely root-controlled. No owner/mode was changed.

Origin remains `git@github.com-infra:Tausendunde1nz/infra.git`; local origin/main is
`3882e143080eda8b0df4813185ba90b74e8b5cc7`. This is recorded separately from the trusted
Control commit. No fetch or remote/ref correction was attempted. The accepted remote
and publisher contract still require clarification; no historical actor search is needed.

## Evidence, preservation and stop boundary

Root evidence: `/var/lib/tu1nz-v11-checkout-attestation-qn5f2hnt`.
Sanitized root-owned report: `redacted/report.json`, 0640 under root:chatops 0750;
parent 0710. The root-private scratch/report/manifest remain private, untouched.
Report SHA-256:
`e51ba590660e8126096369e5d246d3dee95a4ed342b8bcac86fe7bfad2e9aa58`.
An identical 0600 report copy is retained under
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/checkout-attestation-20261002T134042Z/root-run-report.json`.
Only reduced technical findings/path names enter Git; no raw private reports, source
contents, credentials, process arguments or environment values are committed.

The source pins were reverified against the clean worktree and remote 9d1f4f8 before
launch. Bootstrap copied and hash-checked the collector into root-owned staging before
isolated execution. The original index/HEAD/config and metadata were unchanged across
the read. This run performed no checkout, ownership, index, service, token or production
configuration mutation. No rollback is necessary because none was attempted.

Preservation rechecked: 701 baseline files, all 42 hardening files, 1,125 historical
evidence files and 30 V9 sources; 1cf0d79 remains an ancestor. Collector code is unchanged
from the preparation validated by 554 targeted tests and 108 workflow blocks. This
result-only documentation delta requires no repetition of the privileged check.

As explicitly requested for local drift, stop at these current findings. Do not adopt
a new V11 activation baseline, start Agentmode, rotate a token, install a watchdog,
create a PR or prepare cleanup. Next decision is the precise ownership/remote contract
and treatment of the 99 named local entries. Code provenance and tracked-byte equality
are closed; no further broad provenance forensics is needed. The separate V11 production
adapter/watchdog/forward-recovery integration remains pending behind this admission gate.
