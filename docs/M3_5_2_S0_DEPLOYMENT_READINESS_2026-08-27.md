# M3.5.2 — Synthetic STAGING-S0 deployment readiness

Date: 2026-08-27

Scope: versioned readiness contract only

Activation decision: **NO-GO**

## Outcome

M3.5.2 freezes a deployable but deliberately inactive S0 architecture. The
release manifest generator, immutable release gate, hardened manual systemd
oneshot and negative contract tests are implemented in Control SSOT. They do
not install, start, deploy, migrate, connect to a provider or accept real media.

The immutable rollback baselines are Control
`30d5e139ec50b2332cf5aea3bfc5ad4c4c95fcfa` and Adult Core
`dddb94e8ac3d79f6ccd7d696d2fa92da1583850b`, both backed by green remote CI.

## Exact S0 architecture

| Concern | Frozen contract |
|---|---|
| Execution | Manually invoked systemd `Type=oneshot` under deploy user `chatops`; no daemon and no timer |
| Network | No listener, port, DNS, proxy or TLS; `PrivateNetwork=yes`, only `AF_UNIX` |
| Provider boundary | `outbound_providers_enabled=false`; no Telegram/X/Reddit credentials |
| Content boundary | `synthetic_data_only=true`; real media is prohibited |
| Deploy identity | `chatops` may stage a later approved release |
| Runtime identity | Dedicated non-login `tu1nz-adult-s0:tu1nz-adult-s0` |
| Immutable application | `/opt/tu1nz_repos/releases/adult-publishing/application/<application_sha>/` |
| Immutable Control | `/opt/tu1nz_repos/releases/adult-publishing/control/<control_sha>/` |
| Active pointers | `application-current` and `control-current` beneath the common release root |
| Release ownership | root:`tu1nz-adult-s0`, directories `0750`; deploy user has no post-stage write |
| Configuration | `/etc/tu1nz/adult-publishing/staging-s0/config.json`, root/runtime group, `0640` |
| Manifest | Generated as `0600`; installed root/runtime group as `0640` for read-only verification |
| State/media | `/var/lib/tausendunde1nz/adult-publishing/staging-s0`, runtime, `0750` |
| Database | Local PostgreSQL Unix socket `/run/postgresql`, database `tu1nz_adult_s0` |
| Planned DB roles | `tu1nz_adult_s0_owner`, `tu1nz_adult_s0_migrator`, `tu1nz_adult_s0_runtime` |
| Logs | journald evidence for the manual check; no unbounded application log file |

The owner role may own objects but never run the application. The migrator may
apply only exact manifest-bound migrations during a future approved window.
The runtime role receives only the minimum DML privileges after migration.
Role/database creation is not part of this sprint.

## Versioned artifacts

- `scripts/tu1nz_adult_staging_manifest.py` requires clean, integrity-checked
  application and Control repositories, a qualifying backup archive, explicit
  positive RPO/RTO targets and UTC approval. It refuses overwrite and creates a
  mode-0600 staging manifest with a printed evidence digest. A later approved
  installation changes only its owner/group and mode to root/runtime `0640`.
- `scripts/tu1nz_adult_s0_release_gate.py` checks exact Git SHAs, dependency and
  migration hashes, active release pointer, modes/owners, a strict configuration
  allowlist, local socket-only database configuration and synthetic/outbound
  invariants. Both repositories must be clean SHA-named release clones without
  ignored or untracked files. It is read-only.
- `systemd/tu1nz-adult-s0-release-verify.service` is hardened, has no install
  target and has no accompanying timer.
- `tests/test_adult_s0_deployment_readiness.py` exercises positive and negative
  manifest, isolation, path, permission, SHA and activation contracts.

## Server inventory

Tailscale-only SSH reached `chatops@100.121.130.51`. Canonical Control and Core
paths are owned by `chatops:chatops` and mode `2770`. Control is clean at the
expected baseline; Core is clean but stale at
`5572ea165c11fa9d409d1e76ddf08243ae657ea0`. No inspected Docker mount or
service write path targets the planned immutable release root. The host has
systemd 255 and enough current free disk for planning, but disk capacity must be
rechecked against the concrete archive before activation.

The inventory's missing-ripgrep fallback and incomplete unprivileged open-file
coverage are recorded in
`analysis/M3_5_2_SERVER_INVENTORY_2026-08-27.diagnose`.

## Two-phase manifest contract

The Control artifact commit is merged first. A manifest is then generated from
that exact clean commit, the exact clean application commit and the approved
backup. This avoids the impossible requirement that a file contain the SHA of
the commit containing itself. The diagnosis and rationale are versioned in
`analysis/M3_5_2_MANIFEST_SELF_REFERENCE_2026-08-27.diagnose`.

## M3.5 preflight acceptance mapping

| Gate | M3.5.2 result |
|---|---|
| Exact host, VPN and paths | PASS |
| Clean Control baseline | PASS |
| Exact current application on server | BLOCKED — stale checkout |
| No conflicting mounts/services | PASS for inspected scope; privileged open-file check HOLD |
| Immutable application and Control SHAs | PASS in contract; not staged on server |
| Migration and dependency hashes | PASS in contract/tests |
| Synthetic-only, outbound disabled | PASS in contract/tests |
| No listener/proxy/TLS | PASS by architecture and unit contract |
| Dedicated runtime/DB identities | SPECIFIED; not created |
| Fresh qualifying encrypted backup | BLOCKED |
| Business-approved RPO/RTO | BLOCKED |
| Approved retention and cleanup | BLOCKED |
| Restore verification from concrete release | BLOCKED pending backup/manifest |
| P01–P12 against installed release | BLOCKED pending isolated database/release staging |
| Rollback rehearsal | BLOCKED pending first immutable server release |

## Activation blockers and exact next steps

1. Obtain explicit business values for RPO, RTO and retention; version the
   approval without inventing defaults.
2. Perform a privileged, read-only final path/open-file check and capacity check.
3. Create a fresh encrypted backup that includes the exact release inputs and
   pass the existing restore verifier.
4. Stage (do not activate) fresh, clean clones of the exact Core and Control
   SHAs in their immutable SHA paths; never reuse or mutate the live worktrees.
5. Create the dedicated operating-system and PostgreSQL identities with a
   separately approved rollback plan.
6. Generate the manifest from the exact merged Control artifact SHA and record
   its digest.
7. Install the already-versioned artifacts, run the manual release gate, run
   migrations and P01–P12 in the isolated S0 database, then rehearse rollback.
8. Only a fully green evidence set may change the activation decision.

Until all eight steps pass, M3.5.2 is **GO for versioned readiness artifacts**
and **NO-GO for server deployment or activation**.

## Validation evidence

- 42 Control tests pass locally, including the existing restore contract and
  the new staged-layout, rollback, retention, permission and isolation cases.
- 275 unchanged Adult Core tests pass with the project's Python 3.12 virtual
  environment and reviewed `psycopg` 3.3.4 dependency.
- Both repositories pass Python compilation and whitespace validation.
- The Core worktree and remote `main` are identical at
  `dddb94e8ac3d79f6ccd7d696d2fa92da1583850b`; M3.5.2 changes no Core file.
- Remote Control CI and exact-head review status are recorded after the pull
  request completes; server activation does not follow automatically.
