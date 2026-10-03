# V11 process-replay delta — 2026-10-03

**LIVE_NO_GO**; parent `1b964a3fcf467e453215611f7faeca32e1bba3fd`.
Control remains `05b127033d734aa4abce10b2e5b7d513b99ed5d2`, tree
`5459b09c4f986ac947dff1466b490a61238cb676`.

Material correction: initial journal/inhibit parsing was outside the recovery
exception boundary. Missing/corrupt state could bypass the intended secured-stop
path. The admitted recovery now closes and confirms the fence before parsing;
on later errors it closes/confirms again before STOP publication and timer actions.
An unconfirmed fence raises an error and never reports a safe terminal outcome.
Boot-ID syntax is checked before replay. Production Host admission remains false;
its missing independent fence implementation explicitly refuses execution.

Added publication fault hooks at file fsync, no-clobber link publication and parent
fsync. Default hooks perform no action. Added **185 separate-process tests**:
130 hard exits around all 13 step intents/actions/completions (restart and changed
boot ID), 36 hard exits around publication/fsync boundaries, and 19 negative/host
failure cases. Every restart constructs a fresh Store and reads durable records.
Repeated completion preserves journal bytes. nlink=2 after interrupted publication
is deliberately refused; no unproven temporary file is silently repaired/deleted.

Evidence limit: these tests use actual filesystem journal persistence and os._exit,
but model systemd/host steps. They are neither power-loss emulation nor a verified
production cleanup/reboot adapter. Their modeled fence stays closed; they do not
prove successful production fence release or restored live timer availability.

The primary request is **not fully completed**. The guard-only recovery still
cannot safely remove its own execution/boot dependencies and guarantee re-fencing
after late cleanup failure. An independently surviving root dispatcher, authenticated
saved-host hydration and bounded unit permissions remain missing. The full real-host
ACL/timestamp/cleanup crash matrix is therefore incomplete. This is the remaining
unsecured recovery boundary, not a passed milestone. Later V11 integration phases
were not started, and no admission flag or previous safety check was relaxed.

Validation: **2164/2164 targeted tests**, **108/108 workflow steps**, original PR68
**35/35**, original PR69 **7/7** (real Linux ACL/descriptor cases, no skips), governance
**8/8**. Two optional Application cases remain skipped because both expected
checkouts objectively remain absent. Existing post-seal/fence/watchdog tests pass.
A trailing blank line found by diff-check was removed from the test file after
the suite; its parsed AST is identical. Final source map:
`eb72d9cc267a327ef9da178194954320d9aa078fda4370789f28c197bf395597`.
Aggregate suite-result SHA-256: `ebc0b967840bcc744df0a389a69d31024bd603bdc77e961e148eb06c27b26ac9`.

Preservation: 42 Hardening files, 701 historical tracked baseline files, 1125 private
evidence hashes and 30 V9 sources identical; `1cf0d79` remains an ancestor.
Existing tracked documentation unchanged. Production detached HEAD and index match
the confirmed baseline. No claim of a new full live-health inventory.

Private backups and compressed verification: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-replay-20261003T024814Z`.
Offline rollback: revert this commit or restore only its backed-up source files;
new test files need not be deleted. Historical records remain untouched.
No services, containers, credentials, permissions, network/firewall/SSH/Tailscale or
live watchdog changed; no protected sudoers/gshadow collection, PR or merge.
No unavoidable user input is due while the independent dispatcher remains unfinished.
