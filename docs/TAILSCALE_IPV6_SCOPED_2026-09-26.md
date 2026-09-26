# Scoped tailscale0 IPv6 preflight — 2026-09-26

Authorization: persistent enablement exclusively on tailscale0. Global/default disable_ipv6, all other interfaces, public IPv6, Docker, provider firewall and Tailnet policy must remain unchanged.

Current stage: protected backup and isolated namespace test ONLY. No live activation script or service is installed. The test cannot establish that tailscaled will configure IPv6 when the global capability flag remains disabled.

Reviewed script: scripts/tu1nz_tailscale_ipv6_scoped_preflight.py
Server protected execution copy: /opt/tu1nz_repos/network-hardening-private-2026-09-22/ipv6-scoped-20260926T065529Z/scoped-preflight.py
Evidence: same directory /evidence, directory 0700, files 0600. Full Tailscale preferences are kept only in this protected backup and must never be displayed or committed.

Operations: capture interface flags, IPv4/IPv6 addresses/routes/rules, listeners, firewall rules, Tailscale status/preferences/version/unit, persistent sysctls and UFW files with owner/mode/hash, Docker network definitions and container state (excluding environment/secrets). Invoke one unshare --net child; no named network namespace, public connection, container change, daemon restart or host network write.

Isolated tests: create a dummy tailscale0 in a disposable netns; disable it; record baseline; reject global/default/wildcard/path-traversal/other-interface targets and invalid values; enable exactly the target twice; assign an explicit test-only IPv6 and route; complete a local TCP exchange; restore disable flag; compare addresses/routes and reference-file contents/permissions to baseline; confirm absent-interface refusal. Explicit addresses/routes are only for the isolated test, not a proposed live workaround.

The parent compares all host interface flags, links, IPv4/IPv6 addresses, routes and policy rules before/after. Any failure blocks progression. The child namespace is discarded on exit; staged artifacts remain as evidence. Rollback removes only newly created test artifacts; no existing live file is replaced. Live rollback/persistence and automatic rollback are not yet implemented or proven by this preflight.

Gate: after test success, separately design persistence and a live transaction with an automatic rollback. Do not activate without reviewed backups, exact baseline recheck, documented/pushed code and successful tests. Missing expected Tailscale IPv6/address/route or any change outside tailscale0 must cause immediate rollback. No Phase 5 until the full dual-stack baseline and restart proof pass.

Repository: clean hardening HEAD 77955e1; control-main remains 41478902234c2e901f83668cfe88a57cf52e73d4. Canonical detached checkout unchanged. Only this document and the reviewed preflight script are included in the preparation commit.
