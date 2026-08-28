# M4.25 — Stopped Unit Refresh / Single-Start Guard

Date: 2026-08-28

Decision: **GO only for versioning, a new full encrypted backup with isolated
restore proof, and a stopped byte-exact unit refresh; NO-GO for first start,
enablement, providers, tokens, real media, real payments or publication**

## Goal and boundary

M4.25 changes only the already installed, never-started commercial S0 candidate
unit from `Restart=on-failure` with an infinite runtime to the exact
single-start guard required by M4.24:

- `Restart=no`;
- `RuntimeMaxSec=180`;
- no `RestartSec`, `OnFailure`, `[Install]`, `WantedBy`, timer or auto-recovery;
- unchanged `PrivateNetwork=yes`, `IPAddressDeny=any` and
  `RestrictAddressFamilies=AF_UNIX`;
- `loaded`, `inactive`, `dead`, `static`, `NRestarts=0` and no start timestamp,
  journal, runtime status or lock before and after the refresh.

M4.24 remains historical and unchanged. Its contract stays `active=false`,
`first_start_approved=false` and `decision=NO_GO`. M4.25 does not authorize the
first start or change the product boundary: the database and filesystem remain
synthetic, Telegram intake remains disabled, and no provider, token, real
media, real payment or publishing path is enabled.

## Preflight and no-parallel-activity gate

Before any server mutation, the transaction requires the exact old installed
unit, manifest and active Control release, plus an inactive candidate with
zero restarts and zero start evidence. PostgreSQL, persistent S1 and the daily
encrypted-backup timer must be active; the backup service must be idle. The
commercial schema and six synthetic bootstrap counts are exact. No candidate
timer, trigger or process may exist.

The new immutable Control release is prepared as a separate Git commit after
local regression and green Draft-PR CI. The canonical `control-main` checkout
and Draft PR #33 are not modified or merged.

## Backup and restore gate

After the new release is versioned and staged, but before the installed unit is
changed, the standard encrypted backup service creates a uniquely named
archive. It contains canonical Control, application sources, the immutable
commercial Application/Control/Venv release sets (including the new versioned
unit), configuration, state and custom-format PostgreSQL dumps for S1 and the
commercial candidate. The local SHA-256 must equal the streamed decrypted
remote SHA-256.

`restore-test` rejects absolute paths, traversal, duplicate members, hard
links, devices, FIFOs and writes through symlinks. It then restores the exact
new Control release, application, venv, commercial configuration/state and
both database dumps into a new root-private directory. The restored unit and
state hashes must match, and both dumps must pass `pg_restore --list`.

Only after that proof may a new release manifest be generated for the exact
new Control SHA, unit SHA and backup. The dynamic archive, manifest and runtime
evidence are recorded in a later M4.25 evidence-only commit, avoiding a
self-referential release hash.

## Installation transaction

The versioned controller preserves root-private copies of the old unit,
release manifest and `control-current` target. It then installs only the new
manifest and unit, atomically advances `control-current`, and performs
`systemctl daemon-reload`. It never starts, restarts, enables or stops the
candidate. Post-checks require byte equality with Control SSOT, effective
`Restart=no`, effective `RuntimeMaxUSec=180000000`, release-gate success and the
same stopped/never-started/database/S1/backup boundary.

Because systemctl may present the same effective duration as `3min`, the
controller reuses the M4.24 duration parser and compares the normalized value
to exactly 180000000 microseconds. A `resume-verify` mode can continue only an
exact `daemon-reloaded` partial boundary with intact rollback evidence; it
performs no second installation and only records `verified-stopped` after the
complete post-check passes.

Each completed boundary is written to a root-private `phase.txt`. Any mismatch
stops immediately and preserves evidence. There is no automatic rollback or
quick live correction.

## Abort and rollback plan

If a phase fails, retain the immutable release and evidence, create an M4.25
diagnosis and inspect the stopped state. The separately callable `rollback`
mode is permitted only while zero start evidence remains. It validates the
saved old digests, restores the old manifest and unit, atomically restores the
old Control link, performs only `daemon-reload`, and re-proves the exact old
stopped boundary. It does not delete the new release or evidence.

## Deliberate next approval point

M4.25 ends with the candidate stopped. A later sprint must create a fresh
first-start authorization/acceptance contract that binds the M4.25 release,
unit, manifest and backup evidence and re-runs the complete M4.24 preflight.
Actual first start, PR merge, deployment activation and production use remain
blocked until a new explicit operator authorization.
