# Commercial S11.2-R15.14.1 immutable freeze provenance

## Scope and cause

R15.15 stopped fail-closed at `S11_2_FREEZE_PROVENANCE_RED` before SSH,
sudo, backup, runtime mutation, database access, technical probes, S11 Canary
or Yoti. The historical annotated tag
`s11-2-r15-14-gate-error-envelope-freeze-r1` points to the intended R15.14
merge commit, but its annotation matches only 22 of the 29 exact bindings
consumed by `require_local_freeze()`.

The seven absent canonical names are:

- `runtime_controller_sha256`
- `runtime_gate_sha256`
- `runtime_orchestration_sha256`
- `controller_unit_sha256`
- `controller_timer_sha256`
- `runtime_access_contract`
- `umask_077_regression`

Five non-canonical aliases were written instead:
`controller_sha`, `gate_sha`, `orchestration_sha`, `controller_unit_sha` and
`timer_sha`. The old tag is historical evidence and must remain object-,
target- and annotation-identical.

## Corrected contract

The replacement controller-bound tag is
`s11-2-r15-14-1-freeze-provenance-r1`. The controller references that exact
name. `scripts/tu1nz_adult_public_s11_2_freeze.py` owns the ordered 29-key
generation and verification representation. The regression suite extracts
the binding literals from `require_local_freeze()` and requires exact ordered
equivalence with that representation.

The verifier requires every canonical key exactly once, rejects aliases,
duplicates and unknown binding lines, and independently recalculates the
Control tree and five artifact SHA-256 values from the tagged commit. The
Application commit and tree remain
`db87896697d56b24f192fc1cd0324b6fe46d734b` and
`b915a04e19eef8a244c300b16577a44cea89e2ab`.

## Immutable creation order

The tag annotation is not precomputed from the branch head. After merge and
green post-merge CI, the helper reads the final merge commit, final tree and
artifact bytes, emits the minimal annotation, and the new annotated tag is
created and pushed once. Local verification and a fresh isolated fetch from
origin must agree on tag object, dereferenced commit and annotation content.
The historical tag is checked again afterward.

## Boundaries and readiness

This correction is source-only. It performs no runtime access, SSH, sudo,
server backup, database access, technical probe, S11 start, Canary start or
Yoti access. R15.15 runtime readiness becomes true only after the actual new
local and freshly fetched remote tag pass the exact 29/29 check. R15.15 itself
still requires separate authorization.

Real AVS, adult media and submission, community adult media, external
publishing, payments, Controlled Beta and adult production remain closed.
