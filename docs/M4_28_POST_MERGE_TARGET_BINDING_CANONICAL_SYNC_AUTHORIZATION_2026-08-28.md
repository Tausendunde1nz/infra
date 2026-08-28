# M4.28 — Post-Merge Target Binding & Canonical Sync Authorization

Date: 2026-08-28

Decision: **post-merge target and authorization design complete; NO-GO for
server contact and canonical Control sync**

## Scope and hard stop

M4.28 binds the actual merge result of PR #36 and defines the evidence and
authorization gates for a later Control-only fast-forward. The sprint changes
only the local/GitHub Control repository. It does not contact the server,
capture live evidence, approve a sync, fetch on the server, mutate the server,
or authorize any first start.

The bound target is repository `Tausendunde1nz/infra`, branch `control-main`,
commit `7710acfbadb50ca7a143d6dce84c6556ddf9cb84`, tree
`c226e2dca456d79b1aeef377b3a380d68f83c396`. Its parents are the reviewed
M4.27 base `6f47780eb3b21b369db69a65962e0b3d86107deb` and PR head
`d23a07b3a729e4957587c7e72c56f4d43d2de9d7`. Post-merge CI run
`33205253300` passed.

The committed M4.28 authorization is deliberately `active=false`,
`sync_approved=false`, `approved_at=null` and `decision=NO_GO`. It cannot
authorize a server action without a new explicit approval and fresh evidence.

## Phase A — immutable post-merge binding

The contract binds:

- repository, branch, merge SHA, tree, both parents, PR and post-merge CI;
- last historical server observation at `132d971d…`, tree `c50ce730…`;
- exact SHA-256 values of the M4.24, M4.25, M4.26 and M4.27 contracts;
- application SHA/tree and installed Control SHA/tree;
- installed unit, manifest, state, encrypted archive, archive inventory and
  isolated restore evidence;
- all 23 ignored top-level names and their canonical name-list digest.

The gate derives an immutable-profile digest after normalizing only the future
authorization fields. Any target, release, rollback, ignored-baseline, product
boundary or transaction change therefore fails even for a later approved
authorization document.

## Phase B — exact future mutation scope

The only future mutable checkout is `/opt/tu1nz_repos/control`. Only its Git
metadata and tracked worktree may change. A later transaction must fast-forward
the freshly revalidated `control-main` source to exactly `7710acfb…`; no other
target is accepted.

The following remain unchanged:

- installed `tu1nz-adult-commercial-s0.service` unit;
- all of `/etc/tu1nz` and systemd;
- application, installed Control/`control-current` and venv releases;
- PostgreSQL, state and backups;
- services and timers;
- providers and tokens.

No checkout cleanup, force, rebase, release-link update, unit action, daemon
reload, provider access or first-start action is part of the transaction.

## Phase C — fresh pre-sync evidence

Fresh evidence is valid for at most 300 seconds and must be captured through
Tailscale from the exact host `ubuntu-8gb-nbg1-2` / `100.121.130.51`. A read
error is a hard failure and secret values may not be captured.

The evidence must prove all of the following:

1. candidate remains never started;
2. unit is loaded, inactive/dead/static;
3. `Restart=no`, runtime maximum 180 seconds and `NRestarts=0`;
4. no start timestamps, journal, runtime status or lock;
5. checkout path is exactly `/opt/tu1nz_repos/control`;
6. branch is `control-main` at expected source `132d971d…` / `c50ce730…`;
7. tracked status is clean and Git integrity passes;
8. source is an ancestor of the bound target and fast-forward is possible;
9. all 23 ignored entries exist in exact sorted order;
10. complete recursive ignored inventory is generated and baseline-matched;
11. no incoming tracked path collides with ignored/untracked material;
12. no process, open writer, service or timer can alter the checkout;
13. repository, branch, target SHA and target tree match M4.28 exactly.

The known historical source is intentionally exact. If the server has
legitimately advanced, M4.28 fails closed and a new reviewed source binding is
required; the gate does not silently accept another ancestor.

## Phase D — evidence and rollback before mutation

After a separate authorization but still before the fast-forward, the future
controller must create a timestamped root-private directory below
`/opt/tu1nz_repos/backups/m4-28-control-sync/`. It must contain:

- source and target SHA/tree;
- recursive ignored inventory;
- tracked status and Git-integrity evidence;
- a rollback ref pointing exactly to the source;
- a verified Git bundle containing both source and target histories;
- proof that authorization and the never-started state were revalidated;
- proof of zero incoming tracked collisions.

The pre-mutation gate rejects a missing/invalid bundle, wrong rollback ref,
non-private evidence root, changed ignored inventory, stale evidence, target
drift or authorization drift.

Rollback may restore only the prior tracked Control tree and branch reference.
It must preserve all ignored/untracked material and all evidence. `git clean`,
unit/service/database/release mutation and evidence deletion are prohibited.

## Phase E — future transaction order

Only the following exact sequence is designed:

```text
read-only pre-sync fully green
→ separate authorization gate
→ create root-private evidence
→ fetch control-main only
→ reverify target SHA/tree
→ verify ancestry and collisions
→ fast-forward control-main only
→ verify HEAD equals target
→ verify tree equals bound tree
→ verify tracked clean
→ verify ignored recursive inventory byte-identical
→ verify Git integrity
→ verify M4.24–M4.27 hashes
→ verify unit/manifest/state/backup/restore unchanged
→ verify candidate remains never started
```

The later implementation may use only an exact fast-forward merge. Pull,
force, rebase, squash, cleanup and any secondary mutation are outside the
authorization.

## Phase F — authorization boundary

The checked-in contract is a closed authorization template. A future approved
form must be separately reviewed and must:

- set `active=true`, `sync_approved=true` and decision
  `GO_SERVER_CONTROL_SYNC_ONLY`;
- bind the exact freshly observed source SHA/tree and observation timestamp;
- be approved after that observation and remain no older than 300 seconds;
- preserve every immutable M4.28 target, release, rollback and product field;
- keep `first_start_approved=false`, `no_swap_risk_accepted=false` and the
  separate-first-start requirement.

Authorization-ready does not mean mutation-ready. The latter additionally
requires fresh root-private evidence, exact rollback ref, verified bundle,
unchanged recursive inventory and another never-started check.

## Phase G — tests and CI boundary

Synthetic tests cover wrong target SHA/tree, wrong source branch, dirty state,
non-fast-forward/nonancestor state, Git-integrity failure, missing/changed
ignored material, incoming collisions, bundle/ref failures, prior candidate
start, active or weakened unit settings, runtime status/lock/timestamp/journal,
wrong Tailscale identity, checkout mutators, absent/stale/predating approval,
noncanonical contract path, manipulated contract and pre-mutation inventory or
time drift.

CI requires the committed contract to validate only as NO-GO. Both
authorization-ready and mutation-ready CLI modes must fail without new
evidence. A static guard prohibits host, network, write, service-control and
provider surfaces in the gate.

## Current blockers and next gate

Current blockers are:

- `FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED`
- `FIRST_START_NOT_APPROVED`
- `FRESH_PRESTART_NOT_EXECUTED`
- `FRESH_PRESTART_REVALIDATION_REQUIRED`
- `FRESH_SERVER_SOURCE_REVALIDATION_REQUIRED`
- `NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START`
- `SERVER_CONTROL_SYNC_NOT_APPROVED`
- `SERVER_CONTROL_SYNC_NOT_EXECUTED`

Stop after local validation and Draft-PR CI. The next separate gate may only
review/merge M4.28. Actual server contact, live evidence capture, sync
authorization and server fast-forward each remain outside this sprint. Fresh
prestart, no-swap acceptance, first-start authorization, actual first start and
production remain NO-GO.

## Rollback for this repository-only sprint

Before merge, abandon the isolated feature branch. After merge, use a normal
reviewed Git revert. No server rollback is needed because M4.28 performs no
server action.
