# M4.29.2 — Agentmode maintenance and fail-closed Control protection

Date: 2026-08-28
Scope: `tu1nz_agentmode`, Sync/Health/Integrity and immediately related monitor state
Decision: `GO_MAINTENANCE_WINDOW_ONLY`

## Outcome required

`/opt/tu1nz_repos/control` is the canonical Control SSOT checkout. Automatic
background work may inspect its branch, HEAD, tree, tracked status, refs and
file hashes, but may never update its refs or write its worktree. Only a later,
explicitly authorized Control-sync transaction may change it.

The Adult Commercial Candidate is outside this maintenance scope and remains
inactive, dead, static, never started and at `NRestarts=0`.

## Root cause

The installed `tu1nz_agentmode.service` executes
`/usr/local/bin/tu1nz_sync_all.sh` in a 300-second loop. That script calls
`git fetch --all` followed by `git reset --hard @{u}` for both Docs and Control,
then writes `checksums.txt` and `last_sync.ok` into Control. The nominal
read-only `tu1nz_agent_health.sh --check` path invokes the same script even
though the installed script does not implement a real check mode.

Two dependent mutators amplify the defect:

- `tu1nz_integrity.service` reads the in-checkout marker/checksums, creates
  integrity archives and checksum history inside Control, then commits and
  pushes generated Docs;
- `tu1nz_monitor.service` calls a wrapper that writes `monitor_last.txt` inside
  Control.

The independent `agentmodus_tu1nz.service` only appends to
`/opt/agentmode/agent.log`; it has no Control reference and is not changed.
The active `tu1nz-health.timer` calls a separate read-only system-health script
and is also not changed.

## Preflight and recovery

Tailscale identity was proved as `ubuntu-8gb-nbg1-2` / `100.121.130.51`.
Control was clean on branch `control-main` at
`2c17ae00d9c9b6e057ba36a1766166f7f5549d4c`, tree
`c9408b89f994f1f2fc6f57709bebfb11b767209b`.

The existing encrypted backup from 18:15 UTC did not contain the affected
installed units and scripts. A narrow root-private recovery archive was
therefore created before any service or installed-file mutation:

- path:
  `/var/log/tausendunde1nz/health/recovery/m4-29-2-20260828T204845Z/installed-before.tar.gz`
- SHA-256:
  `fb0c367282d5787cad1b8f1e4caeedf933666050f5ea1b50caf29fa296dbfb18`
- ownership/mode: `root:root 0600`

Rollback may restore these bytes only while the affected services are stopped.
It must never automatically restart the archived unsafe Agentmode. If the new
state cannot be validated, the services remain stopped.

## Target architecture

Runtime state moves to:

- `/var/lib/tausendunde1nz/agentmode/control_update_state.json`
- `/var/lib/tausendunde1nz/agentmode/last_sync.ok`
- `/var/lib/tausendunde1nz/agentmode/docs-checksums.txt`
- `/var/lib/tausendunde1nz/agentmode/notification_state`
- `/var/lib/tausendunde1nz/agentmode/integrity/`
- `/var/lib/tausendunde1nz/agentmode/monitor_last.txt`

Transition-only logs remain under `/var/log/tausendunde1nz/health`. These files
contain no secrets. Directories are `0750`; state files are `0640`, owned by
`chatops:chatops` after installation.

The observer uses `git ls-remote` against `refs/heads/control-main`. This reads
the remote SHA without writing a local remote-tracking ref. It snapshots HEAD,
tree, tracked status and all local refs before and after the query and fails
closed on malformed output, network/Git failure or any detected change.

- equal SHAs: `CONTROL_CURRENT`
- different SHAs: `CONTROL_UPDATE_AVAILABLE`
- no automatic Control sync in either case

The existing automatic Docs fetch/reset policy is deliberately retained only
for `/opt/tu1nz_repos/docs`. `--check` performs no Docs sync, creates no state
directory, writes no log and sends no notification.

The systemd units add an OS-level `ReadOnlyPaths=/opt/tu1nz_repos/control`
boundary. Integrity also receives a private network and writes only external
manifests/state. Monitor output is moved to the external state root.

The pre-existing `/etc/tu1nz/ssot.checksum` is stale. It remains unmodified and
is reported by Agent Health as `LEGACY_MISMATCH`; it is not allowed to override
a successful current Control probe. The new external Integrity result is the
authoritative checksum state for M4.29.2. Removing or regenerating the legacy
reference is outside this maintenance window.

## State-aware behavior

The observer refreshes its external observation and freshness marker each
cycle. A transition log entry and Telegram message are generated only when the
tuple `(status, local SHA, remote SHA, Docs status)` changes. Unchanged
300-second observations generate neither repeated transition logs nor Telegram
spam. Telegram secrets stay in the existing protected configuration and are
never written into runtime state.

## Installation sequence

1. Commit these exact sources and pass Draft-PR CI.
2. Revalidate Tailscale host identity and the never-started Candidate.
3. Capture final Control HEAD/tree/refs/tracked bytes/full file inventory.
4. Stop Agentmode, Integrity and the immediately related monitor service.
5. Prove all three stopped and observe at least one previous 300-second period
   with stable Control.
6. Stage exact committed artifacts below the root-private recovery directory.
7. Verify source/staged hashes, install with root ownership and fixed modes.
8. Create the external state directories as `chatops:chatops 0750`.
9. Reload systemd because unit bytes changed.
10. Start Agentmode, wait for a valid external observation, then restart
    Integrity and Monitor.
11. Verify installed hashes, service state and health.
12. Observe at least two complete 300-second Agentmode cycles and prove Control
    HEAD/tree/refs/tracked status and complete checkout file inventory unchanged.

## Test contract

Synthetic integration tests cover current and remote-drift states, absence of
Control fast-forward/ref/worktree/file changes, true read-only Health,
read-only Integrity, external Monitor state, state-aware notifications,
network failure, malformed remote output, runtime permissions, preserved Docs
policy and the unchanged Candidate boundary. CI also validates shell syntax,
systemd units, JSON, artifact hashes and static forbidden-command guards.

## Hard boundary

This maintenance does not authorize or perform a Control fast-forward, PR #38
merge, First Start, no-swap acceptance, provider/token/media/payment activity,
publishing or production. The candidate unit must never be started, restarted
or enabled by any M4.29.2 artifact.
