# M4.29 — Post-Merge Sync Target Refresh & Server Sync Authorization

Date: 2026-08-28

Decision: **new canonical target bound and authorization layers prepared;
NO-GO for server contact, evidence capture and sync**

## Scope and hard stop

M4.29 binds the actual merge result of PR #37 and replaces the obsolete M4.28
planned target only in a new contract. M4.28 remains unchanged historical
evidence with SHA-256
`d74acaf3a07b43f05e9abcbe380626a7a1301281e2c388028a7be7d760ecb6b6`.

This sprint changes only the local/GitHub Control repository. It does not
connect to the server, capture live evidence, authorize contact or sync, fetch
on the server, mutate the server or perform any first-start action.

The new target is repository `Tausendunde1nz/infra`, branch `control-main`,
commit `2c17ae00d9c9b6e057ba36a1766166f7f5549d4c`, tree
`c9408b89f994f1f2fc6f57709bebfb11b767209b`. Its merge parents are
`7710acfbadb50ca7a143d6dce84c6556ddf9cb84` and
`38ae8008f4923cdfedaaa77bff074f9ba81fb6ad`. PR #37 and successful
post-merge CI run `33207033378` are bound.

## Phase A — post-M4.28 target binding

The new M4.29 contract binds:

- exact repository, branch, target SHA/tree, merge parents, PR and CI run;
- SHA-256 values of M4.24 through immutable M4.28;
- application and installed Control SHA/tree;
- unit, manifest, state, archive, archive inventory and restore evidence;
- the exact 23-entry ignored top-level baseline and its digest;
- future transaction, rollback, authorization and product boundaries.

The gate normalizes only future approval/evidence fields before checking the
immutable-profile digest. Any change to target, parents, CI, historical hashes,
release bindings, ignored baseline or safety boundary fails closed.

## Phase B — expected source versus fresh source

`expected_historical_source` is the last read-only observation:

- path `/opt/tu1nz_repos/control`;
- branch `control-main`;
- SHA `132d971dca214dcfa1cf2e3d48fbec172751e937`;
- tree `c50ce73098d344763fd29f12ba077fb24139b38c`;
- observed at `2026-08-28T19:13:59Z`.

`fresh_observed_server_source` is deliberately empty and `present=false`.
Only a later separately approved read-only server contact may populate it.
If the fresh source differs from the historical expectation, there is no
automatic ancestor acceptance and no sync. A new reviewed source binding is
required.

## Phase C — three independent authorization layers

The committed contract remains:

- `active=false`;
- `server_contact_approved=false`;
- `fresh_server_evidence_present=false`;
- `sync_approved=false`;
- `mutation_approved=false`;
- `approved_at=null`;
- `decision=NO_GO`;
- `first_start_approved=false`;
- `no_swap_risk_accepted=false`.

The future gates are deliberately separate:

1. **Contact-ready** permits only read-only Evidence Capture after a fresh,
   explicit and time-bound server-contact approval.
2. **Sync-authorization-ready** requires captured evidence no older than 300
   seconds and explicit operator approval after capture. It still keeps
   `mutation_approved=false`.
3. **Mutation-ready** additionally requires prepared rollback evidence and a
   separate mutation approval after that evidence.

No layer grants First Start, no-swap acceptance or product activation.

## Phase D — future read-only server evidence

After a separate contact approval, and before any server mutation, one
read-only evidence set must capture:

- exact hostname `ubuntu-8gb-nbg1-2` and Tailscale IP `100.121.130.51`;
- checkout path, branch, HEAD SHA/tree and `origin/control-main`;
- tracked-clean status and Git integrity;
- exact 23-entry ignored baseline and full recursive inventory;
- target ancestry and absence of incoming tracked collisions;
- absence of process, open-writer, service or timer checkout mutators;
- candidate never-started state;
- inactive/dead/static unit, `Restart=no`, 180-second maximum, zero restarts;
- no start timestamps, journal, runtime status or lock;
- exact M4.24–M4.28, release, unit, manifest, state, backup and restore
  bindings.

Any read error, omitted field or mismatch is a hard failure. Secret values may
not be captured. The contact authorizes evidence only, never a fetch or sync.

## Phase E — later sync authorization

A separately reviewed `GO_SERVER_CONTROL_SYNC_ONLY` form may be considered
only when all of the following are true:

- contact was approved before evidence capture;
- evidence is complete and younger than 300 seconds;
- fresh source exactly matches the expected SHA/tree and is bound explicitly;
- source is an ancestor of the exact M4.29 target;
- target SHA/tree, tracked status and Git integrity match;
- ignored inventory matches and collisions are absent;
- candidate remains never started and unit boundary is exact;
- operator approval occurs after evidence capture and is still fresh;
- First Start, no-swap acceptance, providers, payment and publishing remain
  closed.

Authorization-ready still does not permit mutation.

## Phase F — mutation-ready evidence

Before a separately approved mutation, a root-private directory below
`/opt/tu1nz_repos/backups/m4-29-control-sync/` must contain:

- a rollback ref pointing exactly to the fresh source;
- a verified bundle containing source and target;
- rechecked identical ignored inventory;
- repeated never-started proof;
- authorization-, source- and target-drift checks;
- exact timestamped pre-mutation evidence.

Mutation approval must be explicit, occur after this evidence and remain no
older than 300 seconds. Missing/invalid bundle, missing/wrong rollback ref,
inventory drift or any source/target/authorization drift blocks mutation.

## Phase G — unchanged future mutation boundary

Only Git metadata and tracked files under `/opt/tu1nz_repos/control` may later
change. The sole permitted operation is an exact fast-forward of the checked
out `control-main` to the bound target using the previously reviewed remote
reference.

Pull, rebase, force, hard reset, cleanup, branch checkout, release-link change,
unit action, daemon reload, database/state change, provider access and First
Start are forbidden.

## Phase H — rollback boundary

Rollback is available only inside a separately authorized sync window. It may
restore the previous source ref and tracked Control tree only. Ignored and
untracked material plus all evidence must be preserved. No service, unit,
database or release may change, and cleanup is prohibited.

## Tests and CI

Synthetic tests cover the obsolete M4.28 target, wrong new SHA/tree,
manipulated PR parents/CI, missing or stale source evidence, absent contact
approval, evidence/authorization ordering, missing or invalid bundle/rollback
ref, source/target/inventory drift after approval, candidate start evidence,
and accidental First-Start or no-swap approval.

CI requires the committed contract to validate only as NO-GO. Contact-ready,
sync-authorization-ready and mutation-ready modes all must fail in the checked
in state. Static guards prohibit host, network, write, service-control and
provider capabilities in the gate.

## Current blockers

- `FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED`
- `FIRST_START_NOT_APPROVED`
- `FRESH_PRESTART_NOT_EXECUTED`
- `FRESH_PRESTART_REVALIDATION_REQUIRED`
- `FRESH_SERVER_SOURCE_REVALIDATION_REQUIRED`
- `NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START`
- `SERVER_CONTACT_NOT_APPROVED`
- `SERVER_CONTROL_MUTATION_NOT_APPROVED`
- `SERVER_CONTROL_SYNC_NOT_APPROVED`
- `SERVER_CONTROL_SYNC_NOT_EXECUTED`

## Exact next gate and rollback

Stop after local validation and Draft-PR CI. Review and merge require a
separate approval. After merge, a new post-merge target refresh is required
before any server contact. The first later server contact must be separately
approved and strictly read-only.

Before merge, discard the isolated branch to roll back this repository-only
sprint. After merge, use a separately reviewed Git revert. No server rollback
exists because M4.29 makes no server change.
