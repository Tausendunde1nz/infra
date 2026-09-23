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
