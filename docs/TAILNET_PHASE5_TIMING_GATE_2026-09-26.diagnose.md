# Phase5 completion timing diagnosis — 2026-09-26

## Third attempt: incomplete observation interval, verified rollback

Transaction phase5-final-live-20260926T134020Z armed13:40:20 UTC and activated13:40:21 UTC. Fresh iPhone post-change confirmation was received for this exact activation: selected server Exit Node, website/internet/DNS and expected public IPv4 all successful. Full automated postcheck passed, including SSH4/6 and prohibited-user denials, monitoring, unchanged containers/services/listeners, public negative ports, and denied Tailnet ports. API diff/test validation passed. Privileged after-20260926T134143Z confirmed unchanged nftables/UFW and loaded Fail2ban2222.

Completion was correctly refused because the stable collector started13:41:31.432999 UTC, only58.291845 seconds after postcheck start13:40:33.141154 UTC, below the required60 seconds. This is an orchestration timing error, NOT firewall drift or a failed service. The initial progress attribution to the firewall comparison was corrected immediately after inspecting individual results. No check was relaxed and no completion marker was created.

ROLLBACK_NOW was requested13:42:10 UTC; independent watchdog restored original13:42:12 UTC, exact bytes and semantic equality, SHA2565c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180. Watchdog exited. Full rollback-health check passed. Fresh privileged rollback snapshot /opt/tu1nz_repos/network-hardening-private-2026-09-22/api-phase5-20260926/rollback-20260926T134345Z confirms unchanged rules excluding traffic counters, UFW and Fail2ban2222.

Current state: original allow-all network policy with identity/chatops SSH action check. Phase5 is NOT complete. Accept transaction and OAuth cleanup have NOT run. Temporary credential/Keychain remain for recovery and pending work; independent Recovery console remains open. No service, host/network/provider setting, container or canonical detached checkout was changed. Activation work stopped after the failed completion gate.

For a future authorized retry, explicitly wait until postcheck start plus at least75 seconds before starting the stable collector, and retain the existing >=60-second completion requirement. A not-yet-ready timing condition must trigger waiting and a fresh health sample, never a fabricated success or relaxed threshold. All evidence must belong to the same active transaction. Protected Mac evidence: /Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z/phase5-final-live-20260926T134020Z/.
