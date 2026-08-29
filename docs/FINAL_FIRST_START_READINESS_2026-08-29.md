# Final First-Start Readiness — 2026-08-29

## Scope

This closes the technical preparation for exactly one network-free, synthetic
first start of `tu1nz-adult-commercial-s0.service`. It does not authorize or
perform that start.

The final runtime authorization is deliberately external evidence. The
versioned read-only prestart collector, builder, validator and controller are
the SSOT; the root-private
runtime contract binds the current canonical Control commit/tree, fresh
prestart evidence, installed release, backup/restore evidence, database,
candidate history, capacity and product boundary.

## Fail-closed boundary

The prepared contract is created with:

- `active=false`
- `first_start_approved=false`
- `no_swap_risk_accepted=false`
- `operator_accepted=false`
- `approved_at=null`
- `decision=NO_GO`

An approved contract requires atomic operator approval and no-swap risk
acceptance. Approval must follow the bound prestart by no more than 300 seconds
and expires after 3600 seconds. A later window therefore requires a new fresh
prestart and a new root-private contract; an old contract cannot be reused.

## One-start window

- exactly one start; no enable, restart or second start
- `Restart=no`, runtime maximum 180 seconds
- READY and health verification, followed by controlled stop
- database, state, release and authorization invariance checks
- network, providers, Telegram intake, real media, payment and publishing off
- synthetic data and synthetic publishers only
- abort path must stop the unit and preserve runtime/journal evidence

## No-swap assessment

The technical recommendation is
`ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START` only when the fresh evidence shows
at least 4 GiB `MemAvailable` and no relevant new load. There is no swap and no
cgroup memory ceiling; the residual kernel-OOM risk therefore requires an
explicit human decision. The tooling never records that acceptance by itself.

## Operational sequence after a separate approval

1. Capture a fresh, complete, read-only prestart evidence file.
2. Build a new root-owned mode-0600 authorization in a root-owned mode-0700 run
   directory using both explicit approval flags and a UTC approval timestamp.
3. Run the final controller preflight against that exact contract.
4. Invoke `execute` only after the separate operator authorization.
5. Preserve all preflight, authorization, READY, health, stop and post-state
   evidence. Never retry automatically.

The current sprint stops before step 4.
