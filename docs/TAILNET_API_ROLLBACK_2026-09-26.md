# Tailnet API rollback preparation — 2026-09-26

## Corrected acceptance model

Host services and OpenSSH 2222 use Tailscale IPv4. The Tailscale userspace SSH proxy on 22 may answer through controlled Tailnet IPv6; authentication/authorization is governed by Tailscale identity and the SSH policy (with network policy also required). An SSH banner is not an unauthorized login. Kernel/default/interface/Docker/public IPv6 settings stay unchanged.

Fresh Mac tests: IPv6 Tailscale SSH chatops succeeded (exit 0, id -un=chatops). root, nobody and daemon each returned exit 255 with explicit Tailscale policy denial. These supersede the banner-as-failure gate in TAILNET_IPV4_ONLY_2026-09-26.diagnose; retain that historical evidence. IPv6 OpenSSH 2222 remains closed under the previously verified baseline. No live policy change or daemon restart occurred.

## Temporary credential and least privilege

Proposed label: TU1NZ Phase5 rollback 2026-09-26. No OAuth credential has yet been created. Do not document client ID or secret. Only label/scopes/create-revoke UTC and verification results belong here. Required scopes confirmed against official documentation: policy_file; devices:core:read; devices:posture_attributes (the write posture scope is a mandatory policy_file dependency). No all/admin/users/DNS/routes/auth_keys scopes. No tags or device ownership changes.

Both client ID and secret are entered with getpass in a real terminal; fallback-to-echo is fatal. They are stored together only in a temporary macOS generic-password Keychain item, using Security.framework directly. They never enter argv, environment, shell history or logs. Credential enrollment refuses to overwrite an existing item. Core dumps are disabled. OAuth access tokens live only in process memory, with refresh there; no debug HTTP logging or raw error response output. No software installation is needed.

Keychain service label: TU1NZ temporary Tailnet policy rollback; account label: phase5-2026-09-26. Real dummy-value add/read/delete succeeded without using an API credential. The actual credential roundtrip is checked during enrollment.

## Mac watchdog implementation

scripts/tu1nz_policy_watchdog.py plus scripts/tu1nz_keychain.py. Local reviewed copies: /Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z/.

Only public HTTPS api.tailscale.com is used, with normal TLS validation, no redirects, no environment HTTP proxies and an explicit endpoint allowlist. Mac ExitNodeID and ExitNodeIP were empty when checked; no server or SSH link is used by rollback. Reconfirm this before every transaction.

GET /tailnet/-/acl is captured as HuJSON bytes and canonical JSON with matching ETags. Protected UTC transaction directory 0700, files 0600, original bytes/SHA256/ETag and candidate preserved before activation. POST /acl/validate accepts only empty/{} success; HTTP200 containing failed tests or warnings fails closed. Every policy POST uses If-Match. Bounded retries: four attempts, 12-second request timeout, 1/2/4-second backoff for transport and retryable HTTP failures. Tokens never appear in evidence.

Run the watchdog as an independent detached Mac process, retaining the PID and transaction directory. Its own process arms the rollback before applying the candidate, and caffeinate -is -w keeps the Mac awake while it lives. SIGTERM/SIGINT request rollback; SIGHUP is ignored. The deadline uses monotonic time after arming. No cronjob or server timer is installed. The Mac must remain powered and connected to the public API; process SIGKILL, power loss and an extended API outage cannot be repaired by a single-process watchdog and must not be represented as guaranteed recovery.

At timeout or local ROLLBACK_NOW marker, revalidate and POST the original exact bytes, then re-GET and validate. Verify raw SHA or canonical JSON equality. A lost POST response is reconciled through readback. Concurrent foreign policy state is never overwritten: record failure and require independent recovery instead. This concurrency gate is mandatory, not permission to overwrite third-party edits.

A completion marker must match transaction ID, candidate hash, full report hash, deadline and current API policy. The report must contain exactly all required positive/negative tests with boolean true and a completion time after transaction start. Accept-stage additionally requires independent logins with no check. Invalid/incomplete/late markers cannot disarm rollback. These are evidence gates, not automatic proof that an operator-entered test result is truthful; attach the actual test outputs before constructing a completion report.

## Tests and activation sequence

14 offline tests PASSED on the Mac, including five-second actual watchdog timeout control flow with a fake API, forced original-policy re-POST, semantic readback, lost response, concurrent edit rejection, bad scopes/redirects/endpoints, HTTP200 validation failure, secure file permissions/symlink refusal, and missing/failed/stale/mismatched completion evidence. This is NOT a real API rollback test.

1. Create the narrowly scoped temporary OAuth credential; enter both values only in the hidden terminal dialog; never inspect the secret page via automation.
2. Run stage=selftest with a fresh directory and short deadline (e.g. 15 seconds) in a detached Mac process. This stage must actually POST the same original, even if already current. Require ROLLED_BACK.json verified, HTTP success via completed API call, readback equality and validate success; then verify SSH, monitoring and iPhone Exit Node. Do not activate Phase5 if incomplete.
3. Fetch fresh live policy/device assignment and Exit Node evidence, derive the precise minimal candidate and its network/SSH tests. Preserve required IPv4-only host access and separately authorized Tailscale SSH proxy behavior. Review fresh control-main, commit/push candidate preparation before activation.
4. Run phase5 with 1800-second window and a protected JSON candidate. Verify ARMED before relying on activation. All required Mac/iPhone/Exit Node/DNS/web/monitoring/Fail2ban/backup/docs/public-port/container/listener/policy-negative results must be present and fresh before COMPLETE.json is created. Otherwise trigger/wait rollback and verify it.
5. Only after phase5 success: a new accept transaction snapshots that successful policy, and changes only the authorized SSH action. Its rollback restores check without discarding the successful network policy.
6. Revoke/delete the temporary OAuth credential in the Tailscale admin UI after final verification; current Tailscale documentation says revocation also revokes its active tokens. Run local cleanup to remove the Keychain item. Verify deletion and that no credential material was persisted to files/logs/Git/history. Close recovery only after cleanup and final documentation push.

No actual OAuth creation, API write, selftest, Phase5 activation or check-to-accept occurred during this preparation. Secrets are not yet present. Existing live policy remains unchanged.

## Repository and references

Starting hardening HEAD f3bc334, clean. Remote control-main observed at 656e85448c500e172cd7f2f3eaa9b54c8a8b0e33; no unreviewed merge or canonical checkout switch. Only intended scripts, tests and this document are committed; an isolated preparation backup records previous absence.

Official references (checked 2026-09-26):
- https://tailscale.com/docs/reference/trust-credentials
- https://tailscale.com/docs/features/oauth-clients
- https://api.tailscale.com/api/v2 (official OpenAPI: policy GET/POST/validate, ETag and If-Match)
