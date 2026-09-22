# Prometheus host route correction — 2026-09-22

Status: preparation only. No live monitoring or firewall changes yet.
The privileged diagnostic gate must establish the exact drop cause before
ACTIVATE.json may be written. A missing gate expires without activation.

## Confirmed topology and constraints
Prometheus: monitoring_default bridge, 172.29.0.4; route to 172.29.0.1 is direct
via container eth0 with source 172.29.0.4. Bridge interface br-5f7adc44a8c3,
subnet 172.29.0.0/16, gateway 172.29.0.1, confirmed by Docker and host routes.
cAdvisor: same bridge, service alias cadvisor, 172.29.0.2, internal 8080.
Internal GET cadvisor:8080/metrics succeeded.
Node Exporter: host network and host PID namespace, PID 2430, argument
--path.rootfs=/, no explicit listen-address argument, existing wildcard TCP9100
listener. Host-local /metrics returns 200 and CPU/memory metrics.
It has no bridge service alias. Changing to a bridge would change the network
namespace being observed; preserve the current host-network metric semantics.
No extra root-filesystem mount is introduced. Existing filesystem metric scope
is not claimed to be a complete host filesystem audit.
Current localhost:9100 and localhost:8080 targets point to Prometheus itself.
The original author intent is unknown. Active target health is down.
Prometheus supports SIGHUP configuration reload; no restart is needed:
https://prometheus.io/docs/prometheus/latest/configuration/configuration/
Host-network deployment context: https://github.com/prometheus/node_exporter

MyChatBuddy/spicymila_bot/RC4/legacy observation is frozen through 2026-09-24.
The Bot healthcheck mismatch 8090 versus internal8080 remains deferred.
Never exec into, recreate, restart or modify those containers.
Do not change Hetzner, Tailnet, public bindings, Compose or Node Exporter.

## Conditional minimal change
Only if active rule traversal/counters/logs establish local INPUT filtering:
allow TCP9100 solely on br-5f7adc44a8c3 from 172.29.0.4/32 to 172.29.0.1/32.
Use UFW's managed command with comment tu1nz-prom-node-20260922.
No eth0/public-interface rule, no broad source network, no forward/DNAT rule.
The packet targets a local bridge address, so INPUT rather than Docker FORWARD/
DOCKER-USER is the relevant hook; confirm active rules rather than assuming it.
Then replace only the two Prometheus target strings:
localhost:9100 -> 172.29.0.1:9100
localhost:8080 -> cadvisor:8080
Reload only Prometheus with docker kill --signal=HUP tu1nz_prometheus.
This is a reload signal, not termination/restart.

The source /32 and bridge are bound to the inspected existing Docker network.
Container/network recreation must revalidate addresses and this narrow rule;
no automatic widening or promise of unchanged dynamically assigned IPs.
Network recreation, static-IP migration and exporter re-networking are outside
this minimal transaction. Existing containers will not be recreated.

## Backups and privileged workflow
Run the reviewed scripts/tu1nz_prometheus_host_route_transaction.py, also copied
byte-for-byte to the protected base /opt/tu1nz_repos/network-hardening-private-2026-09-22/
as monitor-route-transaction.py.
Script SHA256: 22e41042ae346358aaf020d6578982322a0571bebe4e4b01744641fec3e7c06c.
It writes monitor-transaction-UTC/ with 0700 directory and 0600 files.
Captures original Prometheus and Compose, modes/owners/hashes, full UFW archive,
active nft/iptables/ip6tables including counters, route, loaded container
identities/start times/restart counts/ports/health, and listener bindings.
Each UFW write has another user.rules/user6.rules backup. Prometheus original
is backed up before writing and the candidate before rollback.
Private Compose backup may contain credentials and is never printed or committed.
Configuration is written in place to preserve the existing file-bind-mount inode.

The initial privileged stage is read-only except protected backups. It runs a
short expected-blocked probe and captures counter deltas/kernel logs, then
waits up to 30 minutes for ACTIVATE.json. The agent must first inspect all
evidence, confirm the exact cause and rollback viability, append that result
to this documentation, commit and push. No automatic approval from time passing.
The gate includes cause_confirmed, documentation_pushed, config_sha256.
An ABORT marker or timeout ends the runner. No cron, daemon or parallel monitor.

## Preflight and rollback
The candidate already passed the installed promtool 3.7.3 syntax check.
Privileged runner repeats candidate and original syntax validation using stdin.
Original SHA256: 081e1550575ef642607b1823f7e3f91ec63893a1d50dd121e066d562effe51be.
Exact two-string substitution must reverse to the entire original file.
UFW dry-run records the precise add and delete operation; an absent original
rule is expected before activation. Do not overwrite an existing matching rule.
Full UFW files and monitoring state must match captured baseline at activation.
Before config reload, exercise the exact add/delete round-trip and require the
complete original UFW file map to return byte-identically, then reapply.
On any failure restore original Prometheus bytes, SIGHUP it, remove only the
new exact UFW rule, verify original UFW files and default DROP.
Do not flush nftables or restore a whole ruleset over concurrent changes.
Concurrent Prometheus edits cause a stop rather than overwrite.
Terminal hangup/termination signals trigger the same scoped rollback handler.
An abrupt power loss/SIGKILL cannot be handled by an in-process rollback;
protected backups and the open independent Hetzner console remain available.
Rollback returns to the original down-target state, not a claimed healthy state.

## Validation and final gate
Require both targets up without lastError, then 21 samples over 300 seconds
(at 15-second intervals), current scrape timestamps and plausible fresh metrics.
Require unchanged container IDs/start times/restart counts/ports/network lists/
health, unchanged TCP listeners, IPv4/IPv6 INPUT default DROP, Fail2ban port2222.
Before finalization, fresh independent Mac SSH tests on Tailscale22/OpenSSH2222.
The runner waits up to ten minutes for MAC_TESTS_PASSED.json, requiring both
SSH checks and metrics_valid; otherwise it rolls back.
Record COMPLETE.json and append/push actual outcomes.
Provider leases/cost configuration is not touched by any transaction operation;
no cloud API write is present. Do not infer absolute billed costs stay static.
Phase4 remains gated by complete port-consumer inventory and functional tests.
A protected pre-existing unhealthy bot is documented, never silently repaired.

## Git integration
Fetched control-main cedd7ec6648deeaec1468b809e42596c37bd5000 and merged into
the existing hardening branch without rewriting history:
23215356a51870f0a1d540de6b76b141690cc77e.
Canonical detached checkout untouched. No direct control-main/main push.

## Completed unprivileged offline tests
Production config_write function executed only against a protected fixture:
candidate bytes written and complete original restored; inode, ownership and
mode remained identical. Installed promtool accepted original and candidate,
and correctly rejected malformed YAML. Reviewed transaction source compiles
and matches the protected execution copy byte-for-byte. These tests do not
replace the pending privileged firewall-cause and rollback checks.
