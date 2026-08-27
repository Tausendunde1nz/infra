# M3.5.1 restore artifacts implementation

- Date: 2026-08-27
- Scope: local/versioned Control SSOT only
- Runtime installation: **NO-GO**
- Server execution: **NO-GO**
- Product trace: infrastructure evidence supporting `P01`-`P12`; no product
  step or live boundary is removed

## Outcome

The reviewed M3.5 remediation contract now has executable, network-provider-free
Control artifacts:

- a strict Python verifier with a minimal shell entry point;
- an exact STAGING-S0 manifest schema;
- a versioned but uninstalled systemd oneshot design; and
- automated positive and N01-N18 negative contract tests.

The verifier selects only `tu1nz_system_backup_*.tar.gz`, fails ambiguous newest
selection, downloads through an argv-safe rclone boundary, compares retained
source bytes when required, validates SHA-256 and safe tar members, extracts to
a new isolated directory, runs full Git integrity/cleanliness checks, binds both
repository HEADs and migration/dependency hashes to the manifest, invokes a
separately reviewed component verifier, measures RPO/RTO and emits success only
after every required assertion.

Notification failure cannot turn a verified restore into a false failure, and
it is separately visible. Every restore assertion failure is non-zero, emits a
stable error code, omits `RESTORE_VERIFY=PASS` and retains the isolated run
directory.

## N01-N18 evidence

The test suite injects and proves:

1. missing manifest;
2. wrong environment;
3. enabled outbound providers;
4. missing archive;
5. ambiguous archive selection;
6. download failure;
7. byte-compare failure;
8. checksum mismatch;
9. unsafe archive;
10. missing repository;
11. Git object corruption;
12. dirty restored worktree;
13. wrong application SHA;
14. wrong migration/dependency hash;
15. missed RPO;
16. missed RTO;
17. component/database/object/quarantine assertion failure; and
18. notification failure after a successful verified restore.

All fixtures are synthetic and disposable. Tests contain no production remote,
credential, personal data or media.

## Deliberate gates

- No release manifest instance is created because the final application and
  Control merge SHAs, business-approved RPO/RTO and retention are not yet fixed.
- No timer is defined because schedule and retention approval are still absent.
- The component verifier executable remains an application-owned M3.5.1
  artifact and must be reviewed before any service installation.
- The versioned unit is not an installation instruction. Static verification on
  server systemd 255, exact installed hashes, rollback, a fresh encrypted
  current-SHA archive and isolated acceptance remain mandatory.

## Rollback

Before merge, abandon the feature branch. After merge, revert the exact Control
commit. No runtime rollback exists because this change installs, enables and
executes nothing on the server.
