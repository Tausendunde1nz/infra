# M4.24 final code review — Draft PR #33

Date: 2026-08-28

Reviewed head before corrections:
`758b404d5fe69b5395ff6e73cd3542b6da141926`

Scope: authorization -> technical preflight -> exactly one start -> local health
-> controlled stop/abort -> complete post-verification. No deployment, service
start, provider access, real data or contract approval was performed.

## Result

The original draft was not safe enough for a future first-start window. The
review found one critical and seven high/medium fail-closed gaps. The code,
contract, schema, tests, CI guard and M4.24 design were hardened. The existing
installed unit remains deliberately incompatible with execution because it has
`Restart=on-failure` and no finite runtime maximum. That fact is now a third
explicit NO-GO blocker, not an accepted residual risk.

## Read-only server confirmation

The final review queried only the Tailscale target `100.121.130.51`. Host
`ubuntu-8gb-nbg1-2` reported the candidate `loaded`, `inactive`, `dead`,
`static`, `NRestarts=0` and `ExecMainStartTimestampMonotonic=0`; runtime status
and lock were absent. It also confirmed the critical boundary behind C1:
`Restart=on-failure` and `RuntimeMaxUSec=infinity`. Canonical Control remained
clean/synchronized at `8c4e8992a60c215295cf9d0c400afcd9a931f883`.
S1 and the encrypted-backup timer were active; the backup service was inactive.
No server mutation or first-start command was issued.

## Critical

### C1 — automatic restart and unbounded controller-loss window

- File/function: `systemd/tu1nz-adult-commercial-s0.service`, `verify_unit`
- Problem: the exact installed unit uses `Restart=on-failure`, permits three
  starts in its start-limit window and has no `RuntimeMaxSec`.
- Scenario: the candidate exits unsuccessfully or the controller is killed
  after the start. systemd may start it again, or the candidate may remain
  active without a controller able to stop it.
- Impact: the one-start guarantee and mandatory stopped terminal state are not
  technically true.
- Minimal correction: the controller now requires effective `Restart=no` and
  `RuntimeMaxUSec=180000000`; the current contract records
  `UNIT_SINGLE_START_GUARD_NOT_INSTALLED` and cannot be approved in its observed
  state. A later stopped-unit release must update the unit, hashes, manifest and
  backup evidence.
- Regression test: `test_single_start_guard_rejects_restart_and_unbounded_runtime`
  plus the approved-contract single-start negative case.
- Status: code path fixed fail-closed; stopped-unit replacement intentionally
  remains outside this PR and blocks execution.

## High

### H1 — abort could report success while the unit remained active

- File/function: `scripts/tu1nz_adult_commercial_s0_first_start.py`,
  `abort_window`, `ensure_stopped`
- Problem: `UNIT_STOP_TIMEOUT` was swallowed and abort evidence claimed that
  data was preserved without checking it.
- Scenario: stop fails or times out; the script prints the successful manual
  abort marker while the candidate still runs.
- Impact: false safety evidence and an active candidate after a failed window.
- Minimal correction: stop and inactive/dead state are mandatory; failure is a
  critical nonzero result. Database and state preservation are measured against
  preflight evidence and never assumed.
- Regression tests: `test_abort_stop_failure_is_never_reported_as_success`,
  `test_stop_timeout_is_a_fatal_failure`.
- Status: fixed.

### H2 — signals and non-domain exceptions bypassed the complete abort path

- File/function: controller `execute_window`, `execution_signal_guard`
- Problem: only `FirstStartFailure` invoked abort; `OSError`, `KeyboardInterrupt`
  and default `SIGTERM` could rely on one unverified best-effort stop.
- Scenario: evidence storage fails, the terminal disconnects, or systemd sends
  a signal while the service is active.
- Impact: incomplete evidence and no proven stopped terminal state.
- Minimal correction: convert `SIGHUP`, `SIGINT`, `SIGTERM` and every exception
  after the start attempt into the same abort path, keep signal protection
  through abort/finally, and perform a mandatory final stop when abort fails.
- Regression tests: `test_signal_guard_turns_termination_into_controlled_failure`,
  `test_unexpected_evidence_failure_after_start_invokes_abort`.
- Status: fixed. Uncatchable process loss is bounded by C1's required systemd
  runtime maximum.

### H3 — parallel controllers and incomplete pre-start TOCTOU checks

- File/function: controller `contract_execution_lock`,
  `verify_prestart_revalidation`, `execute_window`
- Problem: two controllers could both pass the stopped preflight; only the
  contract hash and canonical Control head were rechecked before start.
- Scenario: a second controller, unit/config/state/database mutation or release
  drift occurs after the first preflight and before `systemctl start`.
- Impact: more than one start command or execution against an unreviewed
  boundary.
- Minimal correction: hold an exclusive lock on the safe contract inode, rerun
  the full preflight immediately before start, compare every stable release,
  unit, contract, state, database and service value, then rerun approval.
- Regression tests: `test_controller_lock_rejects_parallel_execution`,
  `test_prestart_revalidation_rejects_database_content_drift`.
- Status: fixed within the non-root trust boundary.

### H4 — aggregate database counts allowed undetected changes

- File/function: controller `database_snapshot`, `verify_initial_database`
- Problem: one `business_rows` sum did not detect row updates or one table losing
  a row while another gained one; seed contents and schema definitions were not
  compared.
- Scenario: two changes cancel numerically or a row changes without changing
  any count.
- Impact: postcheck accepts database mutation.
- Minimal correction: one repeatable-read, read-only transaction captures exact
  counts for all 39 tables, deterministic SHA-256 content and schema digests,
  function/table counts and zero other database sessions.
- Regression tests: `test_database_snapshot_uses_one_transaction_and_hashes_all_rows`,
  `test_per_table_counts_detect_sum_cancellation`.
- Status: fixed.

### H5 — inherited root environment could alter helpers or expose credentials

- File/function: controller `command`, `verify_provider_environment_boundary`
- Problem: every helper inherited the complete operator/root environment,
  including possible credential and systemd/Git routing variables.
- Scenario: a sensitive variable reaches a child health command, or environment
  configuration redirects a trusted binary to a different service boundary.
- Impact: credential exposure or verification against the wrong target.
- Minimal correction: child processes receive a fixed allowlisted environment;
  sensitive system-manager/unit environment names block preflight.
- Regression test: `test_command_does_not_inherit_sensitive_environment`.
- Status: fixed.

## Medium

### M1 — approval had no expiry or future-time rejection

- File/function: authorization gate `validate_contract`
- Problem: an arbitrarily old approval after the historical observation stayed
  valid, and a far-future timestamp extended validity.
- Scenario: an old GO contract is reused after operational conditions change.
- Impact: execution without current operator intent.
- Minimal correction: one-hour maximum approval age, five-second future skew,
  exact booleans/count types and mandatory single-start observation.
- Regression tests: stale, future, type-confusion and missing-guard contract
  cases.
- Status: fixed.

### M2 — stale READY evidence could be accepted

- File/function: controller `read_runtime_status`, `wait_for_runtime_state`
- Problem: owner/shape were checked, but the status was not bound to the current
  start attempt.
- Scenario: a valid-looking READY file is created before the controller starts
  the unit.
- Impact: health proceeds without proving this process reached READY.
- Minimal correction: require internally ordered UTC timestamps and
  `started_at` at or after the current window start.
- Regression test: `test_runtime_status_before_window_is_rejected`.
- Status: fixed.

### M3 — static CI guard could hide infrastructure failure

- File/function: `.github/workflows/control-validation.yml`, M4.24 static guard
- Problem: shell negation treated both expected `git grep` no-match and grep
  infrastructure errors as success.
- Scenario: grep fails with status greater than one and CI still passes.
- Impact: forbidden behavior may escape the textual guard.
- Minimal correction: accept only grep status one; fail on a match or any other
  status. AST tests also require one literal start, allowlisted systemctl verbs
  and a single centralized subprocess entrypoint.
- Regression test: `test_systemctl_command_grammar_is_literal_and_allowlisted`.
- Status: fixed.

## Low / informational

- Root, the systemd manager, the kernel and PostgreSQL superuser remain trusted
  computing-base boundaries. A privileged actor can always replace or bypass
  local controls; the controller detects ordinary drift but does not claim to
  defend against a simultaneously malicious root.
- The candidate may use only `AF_UNIX`; `PrivateNetwork=yes` and
  `IPAddressDeny=any` remove external IP transport. The local PostgreSQL Unix
  socket is intentionally available. No provider credential is configured.
- Read failures in cron/process/container/open-file inspection now block instead
  of returning an empty result. The dedicated runtime user and database must
  have no other process/session at both preflights and postcheck.
- The hash-bound unit footer still uses historical M4.19 wording that calls the
  unit uninstalled even though M4.23 installed it stopped/static. It changes no
  systemd behavior and must be corrected together with the separately reviewed
  single-start unit refresh so the unit hash, manifest and backup stay coherent.
- PR #33 must remain Draft during this review. Merge, deployment, unit changes
  and first start remain outside this review and require separate authorization.

## Rollback

Before merge: abandon the feature branch or reset review work to
`758b404d5fe69b5395ff6e73cd3542b6da141926`. No server rollback is needed
because this review performs no server mutation. The M4.23 archive remains the
recovery basis.
