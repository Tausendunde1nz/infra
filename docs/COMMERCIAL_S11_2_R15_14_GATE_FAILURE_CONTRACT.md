# Commercial S11.2-R15.14 Gate failure contract

R15.14 is a source-only correction for the diagnostic information loss proven
by the single R15.13 runtime attempt. It performs no server installation,
Technical probe, S11 state transition, Canary start, Telegram action or Yoti
access.

## Root cause and compatibility

The first loss occurred in the S11.2 Gate final exception handler. It emitted
the exception class name, so an allowlist-safe
`S11_2_TECHNICAL_BINDING_MISSING` became `ValueError`. The second loss occurred
in `write_technical_profile()`, which converted every non-zero Gate process
into `S11_2_TECHNICAL_GATE_READ_RED` without validating the captured stdout.

The outer code remains stable for controller compatibility. R15.14 adds the
exact inner safe code, component, classification and process exit status. A
diagnostic improvement never weakens the Gate: any non-zero Gate exit still
stops before Technical probes, S11 installation and Canary activation.

## Gate Failure Envelope V1

`GATE_FAILURE_V1` has exactly these fields:

- `schema=TU1NZ_S11_2_GATE_FAILURE`;
- `version=GATE_FAILURE_V1`;
- `ok=false`;
- an exact allowlisted `safe_code`;
- an allowlisted `component`;
- an allowlisted `classification`.

The Gate inventories every literal canonical `ValueError` in its source. Only
an exact inventory member may cross the process boundary. An unknown
`ValueError` becomes `S11_2_GATE_UNKNOWN_ERROR_RED`; psycopg, OS and JSON
failures become bounded database, I/O and JSON codes. No exception message,
SQL, DSN, hostname, username, path contents or provider output is serialized.

The bounded components are `TECHNICAL_EVIDENCE`, `RUNTIME_CONTROL`,
`RELEASE_BINDING`, `CANARY_STATE`, `DATABASE`, `INPUT_CONTRACT` and
`PROMOTION_BARRIER`. Classifications are
`TECHNICAL_EVIDENCE_BLOCKER`, `STATE_INTEGRITY_BLOCKER`,
`RELEASE_BINDING_BLOCKER`, `INPUT_CONTRACT_BLOCKER`, `DATABASE_BLOCKER` and
`UNKNOWN_HARD_RED`. Classification is diagnostic only and never authorizes an
automatic retry.

## Controller diagnostic V1

The controller captures Gate stdout and the numeric process exit separately.
It invokes the same versioned Gate artifact to validate the result. A valid
non-zero Gate result becomes `GATE_DIAGNOSTIC_V1` with:

- stable `outer_code=S11_2_TECHNICAL_GATE_READ_RED`;
- exact `inner_safe_code`;
- matching component and classification;
- `gate_exit_code` and `contract_version`;
- bounded `observed_at` and deployment `run_id`.

Empty, oversized, non-ASCII, malformed, wrong-schema, wrong-version or
taxonomy-inconsistent output becomes
`S11_2_TECHNICAL_GATE_ENVELOPE_INVALID_RED`. An unknown syntactically valid
child becomes `S11_2_TECHNICAL_GATE_CHILD_UNKNOWN_RED`. A success/failure exit
contradiction becomes `S11_2_TECHNICAL_GATE_EXIT_MISMATCH_RED`. Raw Gate output
is never copied to stderr.

## Successful and RED decisions

Gate process success retains the existing decision payload unchanged. A valid
0/5 or 4/5 Technical profile remains `INSUFFICIENT_EVIDENCE` and produces a
dynamic plan of five or one serial probe respectively. A valid 5/5 GREEN
profile produces no probe. Five valid samples with a RED latency profile are a
successfully read Gate result followed by `S11_2_TECHNICAL_SLO_RED`; this is
distinct from a Gate contract failure.

The same Gate exception envelope applies to Technical reads, Canary evaluation
and promotion-barrier evaluation. Successful promotion semantics are unchanged.

## R15.15 source-only simulation

`scripts/tu1nz_adult_public_s11_2_r15_15_simulator.py` models both next-attempt
paths. The happy path orders Health, dynamic Technical completion, S11 disabled,
eight synthetic journeys, feature-off fallback, rearm, evidence epoch, exactly
one Canary start and systemd handoff. The negative Gate path preserves the exact
inner child, starts zero probes, installs no S11 runtime, starts no Canary and
models exactly one rollback after the mutation boundary. The simulator has no
network, database, systemd, Telegram or server mutation capability.

## Product boundary and next priority

Real acquisition remains active with the unchanged baseline. Community user
content publishing, Adult Media, real AVS, Payment, external publishing,
Controlled Beta and Production remain closed. After a separately authorized
and successful R15.15 S11 handoff, the next product priority is a read-only
Yoti Sandbox environment and credential-existence verification followed by
Sandbox authentication, test-identity and callback/redirect checks. Production
AVS remains closed pending separate authorization.
