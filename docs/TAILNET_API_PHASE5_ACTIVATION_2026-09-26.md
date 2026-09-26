# Phase5 API transaction preparation — 2026-09-26

Status: real API rollback test PASSED; production minimal policy NOT activated.

Temporary OAuth enrollment succeeded through hidden user input and Keychain. Do not record ID/secret. Label TU1NZ Phase5 rollback 2026-09-26; exact policy_file and mandatory devices:core:read / devices:posture_attributes scopes selected; no extra write permissions. Credential cleanup is still pending and must follow completed transactions (or explicit abandonment).

The independent Mac watchdog armed at 09:41:31 UTC and force-reposted the complete current original policy at its deadline. POST/readback/validation succeeded at 09:41:46 UTC, byte-identical SHA256 5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180. No FAILED or ROLLBACK_FAILED marker. This proves the real API read/write/recovery path, not merely a mock. Evidence directory: /Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z/api-selftest-20260926T094130Z/.

Post-selftest 09:42:15 UTC: fresh chatops SSH22/2222 passed; root/nobody/daemon explicitly denied; four internal monitoring endpoints and public website passed; node/cadvisor up with empty errors; backup/docs/health service results success. Current container/listener/provider baseline captured. The existing spicymila_bot unhealthy state is preserved, not corrected or represented as newly healthy. iPhone Exit Node/HTTPS/DNS/current external IPv4 confirmation is still pending.

Fresh public negative baseline: both 91.98.112.14 and 2a01:4f8:1c1a:f152::1 on 22/2222/3000/8080/8090/9100 timed out; no successful connection. This verifies these bounded attempts, not every possible external path.

## Live-derived policy diff

Fresh API policy backup, ETag, device inventory and candidate live under protected Mac phase5-preparation-20260926T094240Z and server /opt/tu1nz_repos/network-hardening-private-2026-09-22/api-phase5-20260926/. Directory0700/files0600. Original grant is src=[*], dst=[*], ip=[*]. Replace it with exactly:

```json
[
 {"src":["100.98.95.69"],"dst":["100.121.130.51"],"ip":["tcp:22","tcp:2222","tcp:80","tcp:443","tcp:3000","tcp:8080","tcp:9090","tcp:9100"]},
 {"src":["fd7a:115c:a1e0::4132:5f45"],"dst":["fd7a:115c:a1e0::7a32:8233"],"ip":["tcp:22"]},
 {"src":["<confirmed owner identity>"],"dst":["autogroup:internet"],"ip":["*"]}
]
```

Owner placeholder is documentation redaction only; actual protected candidate contains the confirmed existing owner. SSH source identity, autogroup:self, chatops-only and action=check remain unchanged. Network scope restricts peer administration to the confirmed Mac and exact server addresses. No public firewall change; no IPv6 host-service grant; IPv6 SSH proxy only. Internet grant retains owner-device exit usage, not general Tailnet peer access. No tags/ownership/posture changes. Monitoring scrapes and cloud backups remain on existing internal/outbound paths.

Built-in candidate tests: allowed Mac IPv4 ports, Mac IPv6 SSH22, forbidden IPv6 host ports, forbidden peer management for iPhones/other Mac, internet access, SSH chatops check and root/nobody/daemon deny. Tailscale Validate endpoint passed. Candidate SHA256 92dfa2c127745da96d4292fbc487719682120dde8be571f3f832b0952d643a4a. Device API confirmed the expected owner, server and Mac/iPhone addresses; current primary Mac and iPhone credentials valid. Older phone/Mac entries remain expired and untouched.

## Remaining pre-activation gates and sequence

Independent Recovery console, held SSH, current public API reachability, Mac no Exit Node selected, iPhone baseline confirmation, privileged loaded Fail2ban port and kernel firewall snapshot. Privileged snapshot helper is strictly read-only, records private before/after state and verifies loaded Fail2ban action port2222. SSH sudo -n confirmed that a new hidden password entry is necessary for this read-only gate; do not infer current loaded firewall rules from old evidence.

After all baseline gates pass, fresh watchdog snapshot and 1800-second deadline; API applies candidate only after arm. Test all required positive/negative cases and compare privileged firewall/listeners/containers. Do not create completion marker until fresh iPhone post-change result and every required test are evidenced. On failure trigger rollback or allow deadline, then validate restoration. Separate check-to-accept follows only after this transaction passes; its baseline is the successful Phase5 policy.

## Git

Clean hardening base8d049a1; current control-main656e854 reviewed: changes since4147890 concern S11/S10 health-code/runtime contracts, manifests, CI and documentation, not this policy or watchdog. A protected verified bundle precedes a non-rewriting merge in the isolated worktree. Canonical detached checkout untouched. Only intended new helper/documentation staged; full private policy/evidence and credentials are not committed.

## Fresh privileged baseline — 2026-09-26 12:08 UTC

The recovery-console read-only snapshot PASSED at12:08:04 UTC: loaded sshd Fail2ban action=nftables and port=2222. Actual nftables IPv4 and IPv6 filter INPUT/FORWARD policies are DROP. Protected server snapshot: api-phase5-20260926/before-20260926T120803Z/. Fresh12:08:58 UTC Mac checks passed chatops22/2222, prohibited-user denials, monitoring, website, targets and service results. Original API policy is unchanged and candidate validation passed again. Mac baseline/evidence: /Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z/final-preflight-20260926T120858Z/.

The extended sequential Mac evidence collector is staged in scripts/tu1nz_phase5_extended_mac_check.py; it cannot write policy or disarm the watchdog. It requires unchanged server baseline, both SSH families with denied users, IPv6 OpenSSH closure, public negative checks, live denied Tailnet ports and, for accept, three new logins without check. It writes evidence even on failure. Separate privileged after-snapshot, policy API tests, iPhone results and stable observation remain required. No activation occurred.

control-main advanced again to0a85e5c4e6228f067730031aba3280dae50645a0; fetched/read-only review shows S11.2 deployment orchestration code, tests, manifest, docs and ignore rules. No policy/watchdog overlap; no new deployment or canonical checkout modification performed here. Prior integration656e854 remains in this branch; later unrelated commits are not merged automatically.

The operator's latest 'fertig' is verified as successful sudo input. It is not treated as evidence that iPhone Exit Node, website/DNS and external IPv4 checks all passed. An explicit bundled iPhone baseline confirmation has been requested. Production activation and watchdog arming remain pending that critical client result. The temporary OAuth credential and Keychain entry are retained solely for the pending authorized transactions; no active production-change watchdog is running and no token is persisted to disk.

## First API activation, verified rollback and Python3.9 correction

User explicitly confirmed all iPhone baseline tests. Watchdog armed12:11:43 UTC; API candidate activated/read back12:11:43 UTC. Initial health checks, IPv4 SSH, monitoring, service results and unchanged containers/provider/listeners passed. IPv6 SSH chatops succeeded and root/nobody/daemon were explicitly denied. The next expected IPv6 OpenSSH timeout raised Python3.9 socket.timeout, which this checker incorrectly failed to catch as builtin TimeoutError. This is a checker compatibility defect, not evidence of an opened host port.

No failure was ignored: ROLLBACK_NOW was written immediately. Automatic restoration completed12:12:18 UTC, exact bytes and semantic match, SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180; no rollback failure. The corrected complete rollback-health check PASSED. Privileged rollback-20260926T121409Z snapshot PASSED: loaded Fail2ban2222 unchanged, actual nftables rules identical excluding packet/byte counter values. Original policy is restored; first Phase5 attempt is NOT successful. Post-change iPhone confirmation was not obtained for that attempt.

Scoped correction: catch socket.timeout explicitly for expected TCP timeouts; no-route/permission errors remain errors and a successful connect remains failure. API retry tuple also names socket.timeout explicitly (already covered by OSError) and a regression proves its four-attempt bound. Seven transport regressions passed under the actual /usr/bin/python3 (3.9), plus all14 watchdog tests passed again. Before-change local/server source backups retained. No server, interface, firewall or container fix applied.

Evidence: Mac phase5-live-20260926T121142Z and protected server correction directory /opt/tu1nz_repos/network-hardening-private-2026-09-22/api-phase5-20260926/python39-correction-20260926T121531Z. Successful checks after restoring the original policy do not count as post-change acceptance. A corrected retry must use a fresh independently armed transaction and require all post-change evidence again before disarming. No check-to-accept yet.
