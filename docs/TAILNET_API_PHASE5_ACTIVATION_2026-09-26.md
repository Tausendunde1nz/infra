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

## Corrected retry preflight — 2026-09-26 12:20–12:23 UTC

Fresh API original is byte exact, SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180. Fresh protected backup: Mac api-rollback-20260926T084526Z/retry-preflight-20260926T122028Z. Candidate remains92dfa2c127745da96d4292fbc487719682120dde8be571f3f832b0952d643a4a and API validation passed. Actual checker SHA25694a517ee02be3a6d2ac4cb649edbbef5ffe4b5f3751fe6228664074e8f9c3e40 matches committed server source. All21 tests passed again on /usr/bin/python3 3.9.6. OAuth used only token, policy read and policy validation endpoints; no broader write.

Fresh SSH/monitoring/website/service/container baseline passed and equals the previous verified baseline. HTTP redirects to successful HTTPS; Mac has no Exit Node selected, preserving an independent control path. Recovery console remains connected. Fresh privileged before-20260926T122229Z passed at12:22:29 UTC: loaded Fail2ban2222, nftables rules unchanged apart from traffic counters. A VNC command-entry error attempted a nonexistent script path, changed no configuration, and was corrected before the successful snapshot. Remote hardening ae0ecab and control-main0a85e5c unchanged; canonical checkout untouched.

Next activation uses a NEW1800-second external watchdog; it writes ARMED before POST. Full post-change matrix including fresh iPhone confirmation remains mandatory. Second transaction may change only SSH action check→accept and its corresponding SSH test expectation; grants, source, destination and users remain identical. Its rollback baseline is the successful Phase5 network policy with check. OAuth cleanup follows only both complete transactions. No activation by this documentation commit.

## Corrected attempt: tests passed, deadline rollback completed

Second transaction phase5-retry-live-20260926T122323Z activated12:23:24 UTC. Full automated post-change matrix passed, as did privileged after-20260926T122453Z comparison, a64-second stable followup and extended monitoring at12:29:38 UTC. However the fresh iPhone confirmation was not received before deadline. No success marker was written. Watchdog restored original at12:53:24 UTC, byte-exact SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180. User confirmation received after rollback has unknown test execution time and is not retroactively counted as transaction completion.

Fresh full rollback check passed at13:35 UTC; privileged rollback-20260926T133836Z passed at13:38:37 UTC, nftables unchanged excluding traffic counters, Fail2ban2222 unchanged. No check-to-accept or credential deletion occurred. New preflight retry3-preflight-20260926T133938Z has fresh exact original backup, validated candidate, matching checker hash94a517ee02be3a6d2ac4cb649edbbef5ffe4b5f3751fe6228664074e8f9c3e40 and all21 tests passed again under Python3.9. HTTP/HTTPS, independent Mac path, SSH, monitoring, containers, listeners and services passed without drift. Connected Recovery remains open.

Remote control-main is now2c69961c231461af8a3fcf20039d016b600bd944 (S11.2 R15.10 Bash deployment rollback safety); fetched and change list reviewed, no policy/watchdog overlap. Existing detached canonical checkout remains detached and untouched. Only this documentation is committed. Next attempt is separately backed up and armed before POST, same validated candidate and full test matrix, including a confirmation explicitly obtained after its activation.

## Third attempt: incomplete observation interval, verified rollback

Transaction phase5-final-live-20260926T134020Z armed13:40:20 UTC and activated13:40:21 UTC. Fresh iPhone post-change confirmation was received for this exact activation: selected server Exit Node, website/internet/DNS and expected public IPv4 all successful. Full automated postcheck passed, including SSH4/6 and prohibited-user denials, monitoring, unchanged containers/services/listeners, public negative ports, and denied Tailnet ports. API diff/test validation passed. Privileged after-20260926T134143Z confirmed unchanged nftables/UFW and loaded Fail2ban2222.

Completion was correctly refused because the stable collector started13:41:31.432999 UTC, only58.291845 seconds after postcheck start13:40:33.141154 UTC, below the required60 seconds. This is an orchestration timing error, NOT firewall drift or a failed service. The initial progress attribution to the firewall comparison was corrected immediately after inspecting individual results. No check was relaxed and no completion marker was created.

ROLLBACK_NOW was requested13:42:10 UTC; independent watchdog restored original13:42:12 UTC, exact bytes and semantic equality, SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180. Watchdog exited. Full rollback-health check passed. Fresh privileged rollback snapshot /opt/tu1nz_repos/network-hardening-private-2026-09-22/api-phase5-20260926/rollback-20260926T134345Z confirms unchanged rules excluding traffic counters, UFW and Fail2ban2222.

Current state: original allow-all network policy with identity/chatops SSH action check. Phase5 is NOT complete. Accept transaction and OAuth cleanup have NOT run. Temporary credential/Keychain remain for recovery and pending work; independent Recovery console remains open. No service, host/network/provider setting, container or canonical detached checkout was changed. Activation work stopped after the failed completion gate.

For a future authorized retry, explicitly wait until postcheck start plus at least75 seconds before starting the stable collector, and retain the existing >=60-second completion requirement. A not-yet-ready timing condition must trigger waiting and a fresh health sample, never a fabricated success or relaxed threshold. All evidence must belong to the same active transaction. Protected Mac evidence: /Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z/phase5-final-live-20260926T134020Z/.

## Monotonic retry correction and preflight

User explicitly authorized another retry with immediate,30,60,90-second observations and a>=90.0-second minimum. Local Python3.9 runtime experiment demonstrated time.monotonic_ns has process-local epochs on this Mac. Therefore watchdog and observer now use time.clock_gettime_ns(time.CLOCK_MONOTONIC), a shared monotonic clock; an actual parent/child test proves the common clock domain. UTC times are labels only and never minimum-duration proof.

Watchdog records observation_start_ns ONLY after POST and complete candidate readback match. External sequential observer starts immediately (within20s required), samples health at monotonic offsets0,31,61,95 seconds, comparing containers/provider/listeners/services to fresh baseline. Each sample retains private evidence hash and start/end nanoseconds. Failure/interruption requests rollback; absent/incomplete evidence cannot disarm. Completion validates four checkpoints, monotonic>=90s, no future/foreign evidence, exact evidence hash, candidate and transaction, full test matrix and remaining monotonic deadline. 95s target supplies a5s buffer. Deadline is2700 monotonic seconds (45 minutes), with UTC deadline informational. Same isolated guard is used for later accept transaction.

All36 tests passed on /usr/bin/python3 3.9.6, including89.9s rejection at observer and watchdog levels, early-process-end/incomplete evidence, missing/early/failed checkpoints, wall-clock jumps and actual cross-process clock. Existing14 watchdog and7 transport tests remain passing. Fresh protected preflight monotonic-preflight-20260926T135423Z: byte-identical original SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180, candidate API validation, SSH/monitoring/website/container/services passed with no drift; Mac independent of Exit Node. Recovery connected and new privileged baseline passed. Source backups and hashes retained privately before edits.

Only helper/test/documentation files changed; no live policy activation by this commit. iPhone confirmation will be requested only after all automated observations and full tests pass, with exact remaining watchdog window. Following successful controlled disarm, fresh SSH/monitoring/public-port/Exit-Node confirmation is required. Then separately backup/apply only check→accept plus corresponding SSH-test expectation; unchanged grants/source/destination/chatops. Failure of second transaction restores only check. OAuth deletion and Keychain/secret cleanup remain gated on both complete successes.

## Expired iPhone window: actual rollback verified, reauthentication required

Monotonic transaction phase5-monotonic-live-20260926T135539Z passed four health samples at2.817,32.898,63.754,97.005 seconds and completed97.007392 seconds monotonic observation. Full automatic matrix and privileged comparison passed. No current iPhone confirmation arrived before expiry; no completion marker was written. Watchdog restored original at2026-09-26T14:40:41.233671Z (16:40:41 Berlin), exact bytes, SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180.

On renewed user request, fresh API read/validate at19:33:40Z independently confirmed that exact original SHA and byte equality; candidate is not live. Protected evidence: Mac api-rollback-20260926T084526Z/resume-evidence-20260926T193340Z. Full rollback collector hit TimeoutExpired before a result because SSH22 now explicitly requests Tailscale check reauthentication. SSH2222 independently succeeds as chatops. Independent collection over2222 verified monitoring targets, backup/docs/health success, unchanged containers/provider firewall/listeners/services and public IPv4/IPv6 negative ports. HTTP/HTTPS passed. The SSH22 authentication gate is pending and is not falsely marked passed or bypassed by changing to accept.

Recovery browser session also expired and displayed Hetzner logged-out page. Login navigation is prepared; user authentication is required before recovery can be re-established. No new policy write/watchdog activation, no check-to-accept, no OAuth deletion. Previous iPhone request is invalid and will not be reused. A fresh45-minute transaction and new iPhone window of at least30 minutes follow completed authentication and fresh preflight. Canonical detached checkout untouched.

## Authenticated fresh preflight — 2026-09-26 20:39 UTC

User completed required personal authentication. Independent new chatops SSH22 now succeeds with no pending check URL; SSH2222 succeeds. Recovery console is connected as chatops. Privileged before-20260926T203612Z passed; actual nftables rules (excluding counters) and loaded Fail2ban2222 equal prior baseline. Current hardening branch clean at a17bd12, remote verified; control-main remains2c69961, detached checkout untouched.

All36 Python3.9 tests rerun and passed. Mac authenticated-preflight-20260926T203900Z contains fresh protected original policy and SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180, byte-identical to verified rollback; candidate validates. Health/containers/firewall/listeners/services equal prior baseline. Checked source hashes remain watchdog187ceaf9d7e1760d2b9587249691ecea8f31283de4b7e85a12bf991da8f2c104, observer547481aa3e9c8e8ff448bfd27638413cde810e2294bb6ca4252961a906aff6ee and extended checker94a517ee02be3a6d2ac4cb649edbbef5ffe4b5f3751fe6228664074e8f9c3e40.

New transaction uses2700-second monotonic watchdog and0/31/61/95-second observations from confirmed readback. Only after automatic matrix passes will a new iPhone request be issued, requiring at least1800 seconds remaining. Older iPhone confirmations are invalid for this new transaction. No accept transition before current iPhone confirmation. Normal reversible diagnostics/documentation/retry steps remain authorized without routine approvals.
