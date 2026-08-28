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
- `docs/M3_9_PERSISTENT_TELEGRAM_STAGING_S1_2026-08-27.md` defines the dedicated
  synthetic-only persistent Telegram environment, immutable paths, backup,
  release gate, activation sequence and rollback.
- `scripts/tu1nz_adult_s1_manifest.py`,
  `scripts/tu1nz_adult_s1_release_gate.py` and
  `systemd/tu1nz-adult-publishing-s1.service` are the fail-closed S1 Control
  artifacts. They authorize no live Telegram/X/Reddit publisher or real media.
