# M4.27 — Canonical Control Sync + First-Start Authorization Preparation

Date: 2026-08-28

Decision: **planning and local preparation complete; NO-GO for server sync,
no-swap acceptance, first-start authorization and first start**

## Scope and non-action boundary

M4.27 defines the reproducible transactions required to move from merged M4.26
evidence to a later first-start authorization point. This sprint changes only
the local Control repository. It does not contact or modify the server, does
not synchronize canonical Control, and does not run a prestart or accept the
no-swap risk.

The planning base is merged `control-main`
`6f47780eb3b21b369db69a65962e0b3d86107deb`, tree
`5a202f8a25f1085e30d264d7323874028a58bae6`. M4.26 last proved the server
canonical checkout at `132d971dca214dcfa1cf2e3d48fbec172751e937`, tree
`c50ce73098d344763fd29f12ba077fb24139b38c`. That is historical evidence, not
a claim about current live state; it must be rechecked read-only immediately
before any sync window.

M4.27 cannot bind its own future merge commit. Therefore the draft deliberately
records `CANONICAL_SYNC_TARGET_REQUIRES_POST_MERGE_REFRESH`. If this branch is
merged before a sync, a new reviewed evidence contract must replace the planned
target with the actual merge SHA/tree. No operator may reuse `6f47780…` merely
because it appears in this preparation draft.

## Phase A — planned canonical-Control sync

### Exact allowed mutation

Only tracked files and Git metadata below `/opt/tu1nz_repos/control` may change.
The installed candidate unit, configuration, state, database, immutable
application/Control/venv releases and all services remain untouched. In
particular, `control-current` remains the installed M4.25 release
`3135197ba4ac577bbb7fd28341d0c2dc845a7ebe`.

The future transaction runs as the Control owner, not as an arbitrary service
account, and only after a separate approval. Its command-level design is:

1. prove Tailscale host identity and candidate never-started state read-only;
2. prove the canonical checkout is `control-main`, tracked-clean and exactly at
   the newly observed source SHA/tree;
3. inventory every ignored entry recursively. For regular files record
   relative path, mode, owner/group, size and SHA-256; for symlinks record the
   target without following it; include every nested ignored directory member;
4. fetch only `control-main` without merge or checkout;
5. prove the fetched SHA/tree equals the separately reviewed post-M4.27 target,
   Git integrity passes, and source is an ancestor of target;
6. reject any incoming tracked path colliding with untracked or ignored
   material;
7. create a root-private evidence directory, a preserved rollback ref and a
   verified Git bundle containing source and target histories;
8. run exactly `git merge --ff-only refs/remotes/origin/control-main` from the
   checked-out `control-main` branch;
9. prove `HEAD`, `origin/control-main`, reviewed SHA and reviewed tree all
   match; tracked status is clean; the complete ignored recursive inventory is
   byte-identical to its pre-sync value; and Git integrity passes;
10. re-prove M4.24/M4.25/M4.26 hashes, installed release links, candidate start
    evidence, manifest, unit, state and backup hashes.

There is no force, rebase, hard cleanup, untracked deletion, service action,
daemon reload or release-link change in the sync path.

### Ignored material preservation

M4.26 recorded 23 top-level ignored entries with name-list SHA-256
`b23591e86c2b43fbc11a376eb3d0a68c19e3979b1538aa4ac50711b598300e89`.
All 23 must exist exactly as re-observed before the window, and their recursive
byte inventory must match before and after. A missing, new, changed or
colliding entry aborts the transaction. No ignored file is deleted, moved or
used as an incoming tracked path.

### Rollback transaction

Rollback is allowed only inside the separately approved sync window, while the
candidate remains never started, and only from the exact failed post-sync
boundary. It verifies the root-private evidence, rollback ref, bundle, old
commit/tree and unchanged ignored inventory. It then restores only the exact
old tracked tree and branch ref, re-verifies old SHA/tree and clean tracked
status, and again compares the recursive ignored inventory. It preserves all
evidence and never runs `git clean`, deletes files, changes a service or alters
an immutable release.

The exact old boundary is currently
`132d971dca214dcfa1cf2e3d48fbec172751e937` / tree
`c50ce73098d344763fd29f12ba077fb24139b38c`; it must be replaced by the fresh
pre-sync observation if the server has legitimately advanced.

## Phase B — fresh read-only prestart

The fresh prestart runs only after a successful canonical sync and must be no
older than 300 seconds when a separate authorization is created. It must be
rerun immediately before any later start. The contract enumerates all 39
checks, including:

- canonical Control, application and installed Control SHA/tree;
- exact manifest, unit, state, archive, archive inventory and restore evidence;
- release gate, native unit verification and the `0.6 SAFE` boundary;
- loaded/inactive/dead/static, `Restart=no`, 180-second maximum, zero restarts,
  zero PIDs/timestamps/journal, no trigger, status or lock;
- no candidate/runtime-user process, timer, cron, Docker mount or open file;
- no sensitive manager/unit environment name and no external network path;
- PostgreSQL and S1 active, backup timer active, backup service idle, no other
  database session and only the documented unrelated `tu1nz-doc.service`
  failure;
- exactly 39 tables, 21 TU1NZ functions, exact synthetic seeds, zero business
  rows and deterministic database/state hashes;
- at least 1 GiB root storage, at least 4 GiB available RAM for the no-swap
  window, and exact Tailscale identity.

Any read error is a failure, not an empty result. Evidence must be captured in
one read-only snapshot with no secret values.

## Phase C — no-swap risk assessment

### Facts

- last observed available memory: 5,948,368 KiB (about 5.67 GiB);
- swap: 0 KiB;
- fresh-window threshold proposed by M4.27: 4,194,304 KiB (4 GiB);
- workload: one Python candidate process, local PostgreSQL over AF_UNIX, zero
  projected submissions, no real media, no provider/network transport;
- `Restart=no` and `RuntimeMaxSec=180` are installed and hash-bound;
- no `MemoryMax` is configured and no empirical first-start peak RSS exists.

An OOM can kill the candidate or an unrelated host process. The 180-second
runtime limit limits duration, not memory, and does not prevent kernel OOM. An
OOM therefore invalidates the window, permits no second start, requires a
verified stop attempt, preserves journal/evidence, and is reported as critical
if the host or another service is affected.

### Recommendation

`ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START`

This is narrowly recommended only if a fresh prestart proves at least 4 GiB
available memory, backup service idle, no other candidate/database activity,
the exact synthetic/network-free boundary, and all stopped-unit guards. The
observed 5.67 GiB headroom is large relative to a single no-media Python/local
database startup, but the absence of empirical RSS and `MemoryMax` remains a
real residual risk.

This recommendation is **not** operator acceptance. The contract keeps
`operator_accepted=false`, `no_swap_risk_accepted=false` and the blocker
`NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START`. Acceptance requires a later
explicit instruction after the fresh prestart.

## Phase D — authorization draft

`manifests/adult-publishing-commercial-first-start-authorization-preparation.m4-27.json`
is a separate immutable preparation draft. It does not alter M4.26. It binds
the current canonical base, installed release, application, unit, manifest,
state, backup, restore evidence, historical contract hashes, pending fresh
prestart, risk recommendation, first-start window and abort boundary.

It remains `active=false`, `first_start_approved=false`, `approved_at=null`,
`decision=NO_GO`. The gate validates this state but rejects sync-ready,
prestart-ready and authorization-ready modes. A later authorization must be a
new contract, not an edit that silently turns this preparation draft into GO.

## Phase E — future single-start window

The only permitted future sequence is:

```text
fresh preflight
→ explicit authorization
→ exactly one start
→ READY
→ local health
→ controlled stop
→ post-state verification
→ evidence preservation
```

The window has no enablement, restart, timer or auto-recovery; it is network
free, synthetic-only, and limited to 180 seconds. Telegram intake, providers,
real media, payment and publishing remain disabled. Success requires the unit
to end stopped.

## Phase F — abort/recovery boundary

After any future start attempt, every error must stop the unit and verify
inactive/dead state, prove no restart, forbid a second start, compare complete
database and state snapshots, preserve status/journal/evidence and leave the
candidate stopped. Stop failure is critical and may never be reported as
success. There is no automatic database rollback or evidence deletion.

## Rollback for this planning sprint

M4.27 makes no server change. Before merge, abandon the feature branch. After
merge, use a normal Git revert. The M4.25 encrypted archive and isolated restore
evidence remain unchanged and bound. No server rollback is needed unless a
future separately approved sync actually runs.

## Exact next gate

Stop after local tests and Draft-PR CI. Separate explicit approvals are needed
for each of the following: refresh/approve the actual post-M4.27 sync target;
execute server-Control sync; execute the fresh read-only prestart; accept or
reject the no-swap risk; create/finalize a separate first-start authorization;
and execute the actual first start. Production remains NO-GO.
