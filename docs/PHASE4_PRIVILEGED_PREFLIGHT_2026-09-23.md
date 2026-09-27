# Phase4 privileged read-only preflight

Docs pipeline is validated and published; no provider change yet.
Fresh ordinary reads show successful encrypted backup and health service.
Independent Hetzner console has been reopened with existing chatops session.
The effective nginx tu1nz.conf is not readable by chatops; nftables and loaded
Fail2ban need privilege. One bounded read-only script captures all remaining
privileged network evidence, rather than separate interactive commands.

scripts/tu1nz_phase4_readonly.py is copied byte-identically to
/opt/tu1nz_repos/network-hardening-private-2026-09-22/phase4-readonly.py.
It writes only a new UTC phase4-privileged-* evidence directory,0700/files0600,
with SHA256 manifest. No command changes configuration, restarts services,
flushes rules, bans users, sends bot messages, or tests public connectivity.
nginx -T is parsed in memory; only selected routing directives are persisted,
never full configuration output. Credential-bearing upstream URLs block output.
A command failure stops the script. No live rollback is required for reads.

The hardening branch merged origin/control-main7c634d3 without rewriting history;
canonical detached checkout was not changed. Incoming R14 probe scripts/docs
are versioned only, not deployed or executed by this task. Existing service and
port dependencies still require final evaluation against the fresh evidence.
Provider candidate/rollback activation remains gated on that evaluation.
