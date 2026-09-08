# Commercial S10.2D-R8.1 retained-state reconciliation

## Decision

R8.1 is a source-and-state reconciliation step. It does not activate the
community, change BotFather, start acquisition, or perform an R8 cutover.

The live source baseline is healthy, but migration 0029/0030 retains one
community member, three lifecycle events, and fourteen latency samples from a
failed target-release acceptance run. All latency rows are bound to the same
release, technical run, cutover timestamp, and `TECHNICAL_ACCEPTANCE` class.
The two community latency samples correlate with the join and rules-acceptance
events inside the provider acknowledgement window. Real acquisition was never
active and its baseline remains null.

The provider correlation is human and non-privileged. A display name is not
used as ownership proof. Database reconciliation is prohibited until the
provider reports that the acceptance identity has left or been removed from
the community.

## Contract

`tu1nz_adult_public_s10_2d_state_reconcile.py` has five relevant properties:

1. It classifies only the exact failed-release acceptance shape. Unknown or
   additional rows fail closed. The live adapter additionally binds the exact
   release, cutover timestamp, and a one-way hash of the technical run ID.
2. It writes exact identifiers and rows only into a root-owned `0700` backup
   directory with `0600` files. Operator output contains counts and safe codes
   only.
3. It creates data and schema dumps before any database mutation and binds all
   artifacts with SHA-256.
4. It locks every affected table and deletes only manifest-bound member,
   event, and latency identifiers. Bulk state cleanup is not available.
5. A completed reconciliation is idempotent. A real-acquisition state is
   preserved and never becomes cleanup-eligible.

The controller now accepts a retained migration 0029/0030 baseline only after
the state contract is green. The provider group-capability gate runs after the
backup preflight but before quiescing or any target mutation. A new
`state-preflight` action validates the next-cutover state without performing a
cutover or requiring BotFather changes.

## Ownership classes

- `INTERNAL_ACCEPTANCE_CONFIRMED`: explicitly authorized internal acceptance.
- `FAILED_RELEASE_TARGET_STATE_CONFIRMED`: acceptance evidence created by a
  failed target release and bound to its release/run contract.
- Unknown or real product state: never reconciled.

For the current R8 finding, the permitted class is
`FAILED_RELEASE_TARGET_STATE_CONFIRMED`. This classification is based on the
release/run/cutover/evidence bindings and lifecycle-to-latency correlation,
not on a Telegram name.

## Live sequence

After source tests, CI, review, merge, post-merge CI, and an immutable freeze:

1. Create and verify the root-only state backup while the current provider
   status is still captured in its private manifest.
2. Have the operator make the confirmed acceptance identity leave the
   community.
3. Verify that Telegram reports `left` or `kicked`.
4. Re-read and lock the exact backed-up live database state.
5. Reconcile exactly once.
6. Run `state-preflight` read-only.
7. Verify public health, timers, services, inactive community, inactive real
   acquisition, null baseline, and closed adult gates.
8. Stop. R8 is a separate future step.

## Failure policy

Any provider, ownership, row-count, identifier-set, release/run, event,
latency, backup, or post-state mismatch stops the operation. No partial
cleanup, guessed ownership, second reconciliation architecture, BotFather
change, community activation, or runtime cutover is permitted in R8.1.
