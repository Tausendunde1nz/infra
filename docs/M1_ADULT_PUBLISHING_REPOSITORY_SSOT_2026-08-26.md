# TU1NZ Adult Publishing M1 repository SSOT

Date: 2026-08-26
Target host: `ubuntu-8gb-nbg1-2`
Status: approved pre-M1 bootstrap decision

## Binding repository decision

- GitHub repository: `Tausendunde1nz/adult-publishing-core`
- Visibility: private (GitHub Free residual risk accepted by the owner on 2026-08-26)
- Canonical server path: `/opt/tu1nz_repos/adult-publishing-core`
- Runtime owner and group: `chatops:chatops`
- Default branch: `main`
- M1 implementation branch: `feat/m1-core-state-machine`

Neither `/opt/tu1nz_repos/control` nor `/opt/tu1nz_repos/infra` may contain the M1 product implementation. Control remains the operational SSOT; Infra remains infrastructure-only.

## M1 scope

M1 may contain only:

- the isolated project skeleton;
- the core data model and migrations;
- the Submission state machine;
- policy invariants;
- automated tests proving the publishing gates.

M1 explicitly excludes Telegram bots, real media, AVS integration, X or other publisher integrations, payment integration, systemd units, secrets or tokens, containers, deployment and production activation.

## Automation boundary

The preflight on 2026-08-26 found no current systemd unit, timer, container mount, cron entry or open file handle targeting the canonical path. Existing automatic Git processes are allowlisted to Docs, Control and named legacy bot repositories. They must not be widened to include `adult-publishing-core` during M1.

Any later automation for this repository requires a separate documented change, commit, validation and approval.

## Backup and rollback gate

M1 implementation must not begin until all of the following are proven:

1. a fresh encrypted backup contains the canonical repository path;
2. the encrypted remote object has a recorded SHA-256 checksum;
3. the object is restored into an isolated directory;
4. the restored Git repository resolves to the expected `main` commit;
5. the final read-only preflight returns GO.

M1 rollback is Git-based: abandon or revert `feat/m1-core-state-machine` and return to the recorded clean `main` commit. No production service or data rollback is part of M1 because M1 has no deployment path.

## Release gate

Creating the repository and proving its backup are bootstrap actions only. They do not authorize M1 product implementation. Implementation requires the final GO result and remains confined to the dedicated feature branch.
