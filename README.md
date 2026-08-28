# TU1NZ Control SSOT

This repository branch is the authoritative, versioned source for TU1NZ control artifacts at `/opt/tu1nz_repos/control`.

Only the explicit allowlist in `.gitignore` is versioned. Existing legacy, diagnostic, secret-like, and generated files in the directory remain untracked by design.

Operational changes follow this sequence:

1. document the intended state here;
2. create and verify a rollback backup;
3. commit and push the change;
4. activate the committed artifact;
5. validate the live state and record the result.

The branch `control-main` in `Tausendunde1nz/infra` is the baseline for this independent Control history. M1 application work must use a separate repository and branch.

Current Adult Publishing infrastructure decisions:

- `docs/M1_ADULT_PUBLISHING_PREFLIGHT_EXECUTION_2026-08-26.md` records the
  completed M1 repository/bootstrap preflight.
- `docs/M3_5_SERVER_CONTROL_PREFLIGHT_2026-08-27.md` records the current
  staging/server preflight and its deployment `NO-GO` decision.
- `analysis/M3_5_RESTORE_FALSE_GREEN_2026-08-27.diagnose` records the open
  installed-restore-script drift without activating a repair.
- `docs/M3_5_RESTORE_REMEDIATION_DESIGN_2026-08-27.md` defines the reviewed
  design, fault matrix and rollback gates for a future repair; it authorizes no
  runtime action.
- `docs/M3_5_1_RESTORE_ARTIFACTS_IMPLEMENTATION_2026-08-27.md` records the
  local/versioned restore verifier, manifest schema, negative contract suite and
  uninstalled oneshot design. Server execution remains prohibited.
- `docs/M3_5_2_S0_DEPLOYMENT_READINESS_2026-08-27.md` freezes the synthetic S0
  host/path/identity/isolation contract and records its activation blockers.
- `scripts/tu1nz_adult_staging_manifest.py` and
  `scripts/tu1nz_adult_s0_release_gate.py` create and verify exact immutable S0
  release evidence. They contain no deploy or activation behavior.
- `docs/M4_18_COMMERCIAL_RUNTIME_CONTROL_READINESS_2026-08-28.md` records the
  fresh Tailscale-only server preflight and the reviewed, still inactive M4.17
  commercial runtime contract. Deployment and activation remain `NO-GO`.
- `manifests/adult-publishing-commercial-readiness.m4-18.json` binds the exact
  unmerged application candidate and fresh host evidence while keeping every
  provider, payment, media, network, installation and server switch disabled.
- `scripts/tu1nz_adult_commercial_readiness_gate.py` verifies that contract and
  the exact application artifacts without modifying either repository or a
  server.
- `docs/M4_19_COMMERCIAL_S0_INSTALLATION_DESIGN_2026-08-28.md` defines the
  immutable commercial S0 release, exact encrypted backup/restore evidence,
  rollback gates and a hardened network-free service design. All M4.19
  artifacts remain local, uninstalled and disabled.
- `scripts/tu1nz_adult_commercial_s0_manifest.py`,
  `scripts/tu1nz_adult_commercial_s0_release_gate.py` and
  `systemd/tu1nz-adult-commercial-s0.service` bind and verify that future
  synthetic-only release without installing or activating it.
- `docs/M4_20_COMMERCIAL_S0_INSTALLATION_PREFLIGHT_2026-08-28.md` records the
  completed Tailscale-only host preflight. Installation remains `NO-GO` until
  least-privilege parent traversal and PostgreSQL peer identity mapping are
  versioned and tested.
- `manifests/adult-publishing-commercial-installation-preflight.m4-20.json` and
  `scripts/tu1nz_adult_commercial_installation_preflight_gate.py` bind and
  validate that read-only NO-GO evidence without server mutation behavior.
- `docs/M4_21_COMMERCIAL_HOST_ACCESS_REMEDIATION_DESIGN_2026-08-28.md` closes
  the M4.20 parent-traversal and PostgreSQL peer design gaps while keeping all
  installation and activation gates closed.
- `scripts/tu1nz_adult_commercial_path_access.sh`, the two versioned
  PostgreSQL fragments and
  `scripts/tu1nz_adult_commercial_host_access_gate.py` define exact future
  apply/verify/rollback behavior. They remain uninstalled.
- `docs/M4_22_COMMERCIAL_S0_INSTALLATION_AUTHORIZATION_2026-08-28.md` records
  the final post-merge host preflight. The technical design is ready for a
  separately approved root window. The operator-approved recovery profile is
  recorded; a fresh encrypted pre-install backup remains the first execution
  gate.
- `manifests/adult-publishing-commercial-installation-authorization.m4-22.json`
  and `scripts/tu1nz_adult_commercial_installation_authorization_gate.py` bind
  that bounded approval and reject missing approval, premature installation,
  activation, networking or backup evidence.
- `docs/M4_23_COMMERCIAL_S0_STOPPED_INSTALLATION_2026-08-28.md`, the exact
  synthetic bootstrap files and
  `scripts/tu1nz_adult_commercial_s0_install.sh` define the reviewed two-phase
  stopped installation. Preparation and the first commercial backup precede a
  new archive-specific release approval; no first-start action exists.
- `docs/M4_24_NETWORK_FREE_FIRST_START_ACCEPTANCE_2026-08-28.md`,
  `manifests/adult-publishing-commercial-first-start.m4-24.json` and the two
  M4.24 first-start scripts define exact read-only prechecks, one controlled
  network-free acceptance window, stopped post-checks and evidence-preserving
  abort behavior. The committed contract remains `NO_GO`; this repository
  state cannot start the candidate.
- `docs/M3_9_PERSISTENT_TELEGRAM_STAGING_S1_2026-08-27.md` defines the dedicated
  synthetic-only persistent Telegram environment, immutable paths, backup,
  release gate, activation sequence and rollback.
- `scripts/tu1nz_adult_s1_manifest.py`,
  `scripts/tu1nz_adult_s1_release_gate.py` and
  `systemd/tu1nz-adult-publishing-s1.service` are the fail-closed S1 Control
  artifacts. They authorize no live Telegram/X/Reddit publisher or real media.
