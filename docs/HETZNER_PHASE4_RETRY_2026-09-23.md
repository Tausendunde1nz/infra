# Phase4 second attempt: preparation

Operator explicitly authorized a complete retry. No second activation yet.
Hardening HEAD contains ffce37dfd0abdc7f43d9bd6e7017324620d53f84.
Actual Mac Python3.9.6 reran all6 checker self-tests successfully.
Mac and repository checker SHA256 match:
9ad7003f8b841b44509554ab4caa73ab923886662bf6a910f75ee2d64500cdab.
Fresh public TCP443 connections succeed to91.98.112.14 and
2a01:4f8:1c1a:f152::1. Therefore no IPv6 matrix omission is accepted.
Fresh provider export exactly equals first attempt's verified rollback state.

New protected server backup:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-retry-20260923T185834Z/
External Mac copy:
/Users/daniel/.codex/tu1nz-recovery/20260923T185834Z/
Full original metadata/attachment, exact rollback rules, candidate and verified
SHA256SUMS are in both locations, directories0700/files0600.
Target remains inbound TCP80, TCP443, ICMP for IPv4/IPv6; remove broad80-8080 and
public22; no UDP expansion. Outbound and Tailnet policy remain unchanged.
Independent console rollback as chatops:
hcloud firewall replace-rules 10043301 --rules-file /opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-retry-20260923T185834Z/rollback-rules.json

One privileged read-only pre/post helper is prepared to avoid repeated sudo
entries. It verifies the previously reviewed collector SHA, captures PRE evidence
and asserts dual-stack INPUT DROP, Fail2ban2222 and chatops-only OpenSSH. It waits
at most30minutes for CHECK_POST, captures fresh POST evidence and exits. It never
changes rules or services. ABORT_PRIVILEGED ends its wait without configuration
changes. The helper and collector write only protected evidence. A separate
externally controlled provider transaction/rollback must be armed before mutation;
this read-only helper is not the provider rollback watchdog.

Remaining before activation: fresh privileged evidence and Recovery confirmation,
external supervisor preparation plus bounded propagation/retry logic, complete
fresh website/SSH/container baseline and reviewed test matrix. Missing results,
no-route or unexpected exceptions must fail closed. No provider activation is
implied by this prerequisite document. Monitoring is currently up/error-free;
Docs, health and backup last results success. No protected container touched.

## Preflight assertion correction before activation
Fresh privileged capture phase4-privileged-20260923T190616Z confirmed both
IPv4/IPv6 filter INPUT DROP and Fail2ban2222. The initial helper mistakenly
included NAT INPUT chains, whose ACCEPT policy does not override filtering.
Corrected helper selects type=filter/hook=input and requires exactly the two
expected ip/ip6 filter INPUT DROP chains. Actual full rules passed; mutations
to ACCEPT, removal of IPv6 and an unexpected extra filter chain all failed.
No provider mutation occurred. The helper will be restarted using the existing
console sudo authorization if still valid; no protection has been loosened.

## Final second-attempt activation plan
Corrected privileged PRE succeeded using phase4-privileged-20260923T190741Z.
A single read-only console process waits for CHECK_POST and will capture fresh
kernel rules, loaded Fail2ban/OpenSSH and listeners after the provider change.
The external Mac supervisor scripts/tu1nz_phase4_mac_supervisor.py establishes
its held SSH control channel and failure handler before launching the server
transaction. It records EXTERNAL_ROLLBACK_ARMED locally before any provider write.
Any external validation exception requests server rollback and, if originals are
not restored, directly invokes exact provider restoration over the held channel.
The server's independent600second missing-ack rollback guard remains in force.
Failure simulation on the Mac injected a post-change supervisor error: external
restore ran once, exact original state verified, failure remained failure.

Actual Mac --preflight passed five domains with DNS, HTTP/HTTPS, redirects and
plausible HTML titles plus two successful chatops SSH paths and three explicit
forbidden-user denials. Actual Python3.9 compiled/executed the supervisor.
After provider readiness allow3seconds propagation; a successful forbidden-port
connection is retried at most twice,3seconds apart, within a90second matrix bound.
Timeout/refused pass; no-route/unexpected error/incomplete set fail. Both public
IP families first require TCP443 success, then all six required blocked ports;
additional5432/5678 probes cover current localhost listeners within the old range.
Exact dual-stack provider rules provide the full80-8080 exclusion proof beyond
those finite probes; do not claim an exhaustive8001-port live scan.
Fresh POST kernel rules must equal PRE after stripping only counters/handles/
metainfo. Listener bindings must match exactly. Require Fail2ban2222, dual-stack
filter DROP, all three Docs/health/backup service results success, Tailscale
Running with no Health errors, monitored targets up, and all container state
fields unchanged throughout. Guard stays active through a stable observation.
Only then write validation acknowledgment, verify COMPLETE and exact final rules,
and write the external completion report. Failed final readback still invokes
external rollback even if the server guard has already completed.

No public direct need for the removed ports exists per operator confirmation.
No application/monitoring listener or protected container is modified. Historic
trendwatch/private-alpha/bot-health defects are outside this transaction and not
represented as repaired. No actual iPhone Exit-Node test is claimed before Phase5.
