# Commercial S11.2-R15.16.4 Technical profile serialization

## Scope and live evidence

R15.16.3 reached the canonical deployment after a green Freeze, staged Gate,
preflight and backup. Its shared Release/Run binding contained zero Technical
rows, one legitimate REAL `DIRECT_BOT_RESPONSE/TELEGRAM_DIRECT` row and no
UNKNOWN or malformed provenance. The Gate correctly reported Technical
`INSUFFICIENT_EVIDENCE` with five missing samples. The controller nevertheless
serialized the REAL row beside `current_valid_samples=0`, so the unchanged
consumer invariant stopped with `S11_2_TECHNICAL_SAMPLE_SET_INVALID`. The
canonical controller rolled back exactly once before probes, S11 or Canary.

Classification: `TECHNICAL_PROFILE_SERIALIZATION_SCOPE_MISMATCH`.

## Corrected ownership

The Gate continues to read the complete bounded DIRECT evidence set and is
the authority for UNKNOWN, malformed provenance, metric validation and
Technical SLO selection. After that validation succeeds, the controller
serializes only canonical Technical rows:

- source `DIRECT`
- evidence class `INTERNAL_TEST`
- sample type `DIRECT_BOT_RESPONSE`
- interaction path `INTERNAL_ACCEPTANCE`
- SLO metric `handler_duration_ms`

Legitimate REAL rows remain unchanged in the same Release/Run binding. They
are neither deleted nor reclassified and never enter the Technical payload.
The REAL and Technical writers are unchanged.

## Snapshot consistency

The serializer compares its Technical-only cardinality with the Gate's
Technical sample count. A mismatch stops fail-closed with
`S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED`. Additional concurrent REAL rows
do not change that count. A concurrent Technical row does, and therefore
stops. A concurrent unknown or malformed DIRECT row is explicitly rejected
with the same bounded snapshot-drift code instead of being discarded. The
fresh serializer snapshot accepts every canonical Gate provenance profile,
revalidates all four bounded latency metrics, and still serializes only the
Technical subset. Canonical SYNTHETIC, HEALTH, PROVIDER_PROBE, REAL and
non-Technical S11 Canary rows therefore coexist without false drift, while a
concurrent malformed metric fails closed. The serializer also recomputes the
Technical p50, p95, p99, maximum, state and reason from the fresh rows and
requires exact parity with the validated Gate profile. An equal-cardinality
row replacement therefore cannot inherit a stale GREEN state. The
orchestration invariant requiring the serialized list length to equal
`current_valid_samples` remains intact as defense in depth.

## Regression and readiness contract

Source fixtures cover zero, four and five Technical rows mixed with REAL;
multiple and concurrently arriving REAL rows; concurrent Technical drift;
all canonical non-Technical profiles; concurrent UNKNOWN, malformed
provenance and malformed-metric snapshot drift; equal-count Technical SLO
drift; deterministic probe
cardinality; dynamic missing counts; and Technical SLO RED. The source-only R15.17 simulator models
five serial Technical probes while REAL remains present, the complete ordered
S11 phase handoff, exactly one Canary start and no automatic retry.

The Freeze keeps 29 canonical keys and advances
`technical_evidence_contract` to
`PROFILE_SCOPED_READER_SERIALIZER_SNAPSHOT_V3`. Its tag is
`s11-2-r15-16-4-technical-profile-serialization-freeze-r1`; historical tags
remain immutable. R15.16.4 performs no Runtime or database mutation, probe,
S11/Canary start, Yoti call, or S12 work. A subsequent R15.17 Runtime attempt
requires separate authorization after merge, post-merge CI, exact Freeze
verification and a green simulator.
