# S11.2-R15.12 Community health envelope

## Root cause

The R15.11 runtime stopped safely with outer code
`S10_2D_COMMUNITY_STATE_RED`, child
`COMMUNITY_CHILD_CODE_MISSING_RED` and exit 44. Application S8 health had set
the Community report RED for a nested event-path failure but had not emitted a
separate canonical child. For non-zero exits the Control reader inspected the
general `S8_DIAGNOSTIC_RED` code first, so the nested reason was not preserved.

## Joint contract

Application `S8_HEALTH_V2` emits the separate
`TU1NZ_COMMUNITY_FAILURE` / `COMMUNITY_FAILURE_V1` envelope with exactly
`schema`, `version`, `child_code` and `component`. Control reader
`CONTROL_COMMUNITY_READER_V2` validates all four fields against existing
allowlists before deriving outer code, decision class, failure class and next
action. A present but malformed envelope never falls back to legacy parsing.

When no envelope exists, only the known nested provider, event-path,
moderation and restriction fields are accepted as
`LEGACY_STRUCTURED_COMPATIBILITY_USED=true`. No free-form output is parsed.
Provider, event path, moderation, restriction and technical runtime latency
use the same fixed priority on both sides. Full-product latency remains
separate.

The predeploy compatibility gate compares the Application writer constants to
the Control reader and parses the release-bound R15.11 fixture before any
health execution. The R15.13 simulator is source-only and performs no server,
database, Telegram, acquisition or Canary action.
