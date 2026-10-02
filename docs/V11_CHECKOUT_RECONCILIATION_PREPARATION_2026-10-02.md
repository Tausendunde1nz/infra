# V11 Control checkout reconciliation preparation — 2026-10-02

Infra base: `79cdc7019a0b9b934aba07281d4e78fda8073819` on
`security/codex-privileged-ops-2026-09-27`. GOVERNANCE_V1_1_ACTIVE.
No production mutation, privileged run, PR, token change or service start in this delta.

## Trusted forward history supersedes the provenance blocker

GitHub API independently confirms [Control PR #65](https://github.com/Tausendunde1nz/control/pull/65),
merged as `b78bb2a753aa815d47a99969668d64960573050b`, tree
`5135053083ceb2e669e5932cf0ff61b3d24dab9d`. The comparison is 17 ahead, 0 behind;
merge base is exactly `9b383960291da469671c3888cfa4fdcc3c33cf01`.
This is accepted code provenance. Do not reset to the old commit or investigate the
historical synchronizing actor. The earlier unknown-code-origin concern is superseded.
The 26 changed paths cover Governance v1.1 and MyChatBuddy controlled-start, network,
phase/reset helpers and related plans/tests. This does not authorize executing those
helpers or altering MyChatBuddy. Detailed V11 impact/pin adoption waits for reconciliation.

## Current narrowly observed contract problem

The local origin is `git@github.com-infra:Tausendunde1nz/infra.git`. That differs from
the GitHub Control repository used for the trusted merge proof. No approved remote
contract yet establishes whether this is intentional; a different URL alone is not
proof of wrong worktree bytes. The report records the discrepancy without changing it.

The last observed index is root:chatops 0600, while .git is chatops-owned 2775 and the
checkout parent is chatops-owned 2770. A file owned by root inside a user-writable
parent can be replaced through the parent. Therefore the index alone does not establish
a root-controlled trust boundary. No documented privileged-only publisher contract
has been established in the scoped V11 material. Do not infer intent from ownership.
No chown, chmod, index rebuild, recursive repair or checkout switch is prepared.

Root access remains necessary to read the current 0600 index and establish the full
requested local index/worktree comparison. The narrow collector is prepared for that
one read. A clean byte comparison cannot by itself resolve the ownership/remote contract.

## Read-only collector and root staging

New files: `scripts/v11_checkout_attestation/{collector,bootstrap,command}.py`, plus
offline tests. Source pins are in the adjacent preparation JSON. Historical collectors
and launchers are unchanged. This is not an activation launcher.

The bootstrap is a narrowly renamed derivative of the tested copy primitive: fixed
source allowlist; no-follow descriptor traversal; source owner/type/link/size/race checks;
fresh root-owned temporary staging; 0600 copied script; SHA-256 verification of copied
bytes before isolated Python `-I -B` execution. Neutral environment, safe PATH, no user
imports. It creates only a new private evidence directory below /var/lib and writes no
production checkout or configuration. The command is withheld until fresh MacBook readiness.

The collector reads the index into root-private scratch and uses a separate minimal
Git configuration. The production .git/config is parsed only with --no-includes; it is
never loaded as Git's operating configuration. Hooks, fsmonitor, untracked cache,
external diff, attributes/textconv and automatic maintenance are disabled or not invoked.
Git verbs are limited to cat-file, ls-files --stage, merge-base --is-ancestor and the
no-includes config listing. No fetch/checkout/reset/clean/update-index/maintenance.
GIT_OPTIONAL_LOCKS=0, no system/global config, no replacement refs, fixed PATH and
neutral HOME. Original object indirection through alternates, grafts, shallow state,
commondir or symlinks refuses the run instead of silently broadening access.

Expected commit and every traversed tree object are content-hash verified. The expected
tree is compared against the copied index and each raw working-file/symlink blob and
executable bit, without invoking filters. This is stricter than a user-configured status
that might hide assumed-unchanged files or rely on filters. All untracked files, including
ignored files, are reported by path only; no payloads or source contents are exported.
Submodules and unsupported tree types are refused rather than claimed clean.

The report includes canonical path, detached/HEAD state, commit/tree, ancestry,
origin/main loose or packed ref if present, origin, index SHA-256 and numeric metadata,
.git/HEAD/config/ref/lock metadata, ACL hashes, own checks' monotonic times and boot ID.
Relevant configuration features are recorded by key and value hash, not raw commands.
A root /proc scan inspects only CWD, writable FD targets and FD flags, never process
arguments or environments. It runs before/after verification. Known writer/lock state
returns ACTIVE_WRITER_OR_TRANSACTION. Missing process visibility remains unproven.
Metadata is compared before/after; a detected concurrent Git/worktree change is drift.
This is point-in-time evidence, not a writer lock, perpetual guarantee or signed report.

## Classification and attestation trust

- TRUSTED_CLEAN_ROOT_CONTROLLED_CHECKOUT requires clean expected bytes/index, complete
  writer visibility, no locks/writers, a protected root-owned ownership chain AND an
  explicitly confirmed publisher/remote contract. The current contract is UNCONFIRMED_MIXED;
  this preparation cannot silently produce that approval from content cleanliness alone.
- TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN covers clean content with unconfirmed ownership,
  incomplete visibility or failed safe collection. Error results explicitly state that
  the local commit was not verified; trust in GitHub is not misrepresented as local proof.
- LOCAL_CHECKOUT_DRIFT covers actual HEAD/index/worktree/untracked/concurrent-state differences.
- ACTIVE_WRITER_OR_TRANSACTION takes precedence when a writer or Git lock is observed.

Root-private reports/manifests/config scratch are 0600 in 0700 directories. A separate
root:chatops 0750 export contains only a 0640 sanitized report; its SHA-256 is printed
and recorded in the root manifest. The bootstrap binds the copied collector checksum.
This is SHA-256-bound, root-produced evidence, NOT a digital signature. Before later
V11 admission the consumer must verify the root-owned path chain, report checksum,
source pin, boot/freshness, current expected commit and successful classification.
No chatops write access to .git is required or granted. V11 admission wiring and the
new production pin are deliberately not changed before the actual report and contract
review. Reports cannot be replayed as permanent authorization.

## Offline validation and next personal step

35 new tests cover clean/unproven classification, index/worktree drift, ignored files,
remote redaction, locks/writers, partial /proc visibility, unchanged index bytes and
metadata, symbolic HEAD, symlinks/hardlinks/parents, object hash mismatch, forbidden Git
verbs, fsmonitor/hook/filter non-execution, ignored config includes, concurrent worktree
change, atomic output, bootstrap owner/ACL/hash/race rejection and Git timeout.
All 554 targeted tests and all 108 existing workflow run blocks passed in an isolated
clone under umask 0022. Existing optional missing paired-application skips remain skips.
Test-manifest SHA-256:
`a32486a3923c9319c7ca23430f871325bebf41ac08068f84d73d2bb9be84f72d`.
Preserved byte-for-byte: 701 baseline files, 42 hardening files, 1,125 historical evidence
files and 30 V9 sources. 1cf0d79 remains an ancestor. No historical evidence was rewritten.

Private preparation evidence:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/checkout-attestation-20261002T134042Z`.
After commit/push and remote verification, ask once for “Ich bin am MacBook bereit”.
Only then supply the one pinned read-only sudo command. Expected duration approximately
1–3 minutes, depending on checkout size and /proc enumeration; no live downtime. No
secret except personally entered sudo password is needed. No “Fertig” gate follows:
automatically validate the report and continue only within the proven state. If the
mixed contract remains unresolved, stop on that concrete finding; do not fix permissions.
V11 remains LIVE_NO_GO and the exposed token remains unrotated pending full forward recovery.
