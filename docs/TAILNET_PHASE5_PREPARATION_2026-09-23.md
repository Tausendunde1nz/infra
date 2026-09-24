# Phase 5 preparation — NOT ACTIVATED

Phase4 completed at 2026-09-23T19:12:01Z. Both iPhone nodes remain expired/offline.
Activation is blocked until the operator reconnects the iPhone and selects
ubuntu-8gb-nbg1-2 as exit node; then establish a fresh client baseline first.
The current network allow-all and identity-only/chatops SSH action check remain live.
The complete draft was displayed in the Tailscale rule/diff previews without Save,
then Discard changes restored the editor; Save and Discard became disabled.
This is NOT evidence of passing Tailscale server-side policy tests. Compiler and
network/SSH tests remain mandatory before any later activation.

## Exact artifacts and intended diff

Protected originals and full candidates (not committed because they contain private
identity/device data):
/opt/tu1nz_repos/network-hardening-private-2026-09-22/phase5-preparation-20260923T191420Z/
current-policy.hujson and rollback-policy.hujson are byte-identical, SHA256
5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180.
SHA256SUMS covers candidate-check.json and future-accept.json too. Directory0700,
files0600 verified. Offline JSON parse, exact rollback bytes and hashes pass.

Replace only the unrestricted network grant with:
1. Current Mac Tailscale IPv4/IPv6 -> main-server Tailscale IPv4/IPv6,
   TCP22,2222,80,443,3000,8080,9090,9100.
2. Confirmed owner identity -> autogroup:internet, all IP protocols, preserving
   internet access through an exit node for that owner's devices.
Keep SSH identity -> autogroup:self, users=[chatops], action=check unchanged.
Add positive/negative network and SSH tests from candidate-check.json.
No wildcard peer-to-peer grant; no direct bot8090,5432,5678,8081 grants.
The actual literal addresses and identity are preserved in the private candidate;
this document is an intentionally redacted explanation, not an importable policy.
Future accept candidate differs in SSH action and corresponding SSH test expectation
only. It is staged for a later isolated change, never activated with this preparation.

## Dependencies and limits

Mac and server addresses and ownership were confirmed from current Tailscale status.
Network IP selectors are not a permanent identity AND device-posture guarantee:
revalidate ownership and address assignment immediately before activation and after
re-enrollment. For Tailscale SSH, the additional owner-only SSH rule constrains user
identity, while the network grant constrains source Mac and destination server.
A host alias would improve readability only, not authorization strength.
No device tag change: tags change ownership and can alter autogroup:self behavior.
A generic macOS posture does not uniquely identify this Mac; unique custom posture
would add attributes/API/plan dependencies and is not introduced here.

The only currently advertised exit node is the main server. autogroup:internet
preserves owner-device exit traffic; it does not pin one specific exit node.
The grants via selector requires tags, so it is deliberately not used without a
separately reviewed ownership/tag migration. Reassess if another exit node appears.
MagicDNS and DNS settings remain untouched; no speculative server-port53 grant.
Prometheus/node/cAdvisor traffic uses the existing internal Docker/host path,
not Tailnet; Grafana/Prometheus administration is granted from the Mac only.
Server cloud backup traffic uses ordinary outbound routing. Public websites and
reverse-proxy traffic remain governed by the unchanged Phase4 provider rules.
No direct public monitoring or health port is needed, per operator confirmation.
The protected bot healthcheck8090-to8080 correction remains deferred until after
the observation; no container modification forms part of Phase5.

## Required test and activation order

1. Reconnect iPhone, verify its current identity, fresh node addresses and expiry;
   update candidate test addresses if changed, back up before edits, recommit/push.
2. Verify clean intended branch, fresh origin/control-main drift, recovery console,
   independent held SSH, current policy hash and current topology. Stop on drift.
3. Baseline iPhone DNS, HTTPS/internet and server exit public IP; baseline Mac
   SSH22/2222, internal monitoring endpoints and unchanged health/container state.
4. Validate full candidate with Tailscale's official policy validator before Save.
   Require Mac/server allowed ports including both IP families; deny Mac unneeded
   ports and other devices' server administration. Test owner/chatops check and
   root/nobody/daemon deny. An absent or unevaluated test is not a pass.
5. Prepare a working independent admin-console restoration path and a bounded
   externally supervised rollback before applying. Keep recovery console and
   established SSH open. Commit/push the exact final reviewed candidate plan first.
6. Apply network grants with SSH check unchanged. Immediately verify fresh Mac
   SSH22/2222, root/nobody/daemon denial, monitoring endpoints, iPhone DNS/HTTPS,
   and actual exit public IP. Verify node/cAdvisor up, backups/services and protected
   containers unchanged. No Telegram/bot test messages. Observe stable scrapes.
7. Any failure: restore the ENTIRE rollback-policy.hujson in the independent
   Tailscale admin console, verify policy readback/hash and repeat prior chatops,
   monitoring and iPhone baseline. Do not change Hetzner or local rules as a shortcut.
   Do not automatically restore over an unrelated concurrent policy edit.
8. Only after all tests pass, disarm rollback; record UTC/evidence and commit/push
   intended documentation on the existing branch. Evaluate the separately prepared
   check-to-accept change only after network behavior is proven; retain owner/chatops.

References: https://tailscale.com/docs/reference/syntax/grants
https://tailscale.com/docs/reference/syntax/policy-file
https://tailscale.com/docs/features/device-posture
https://tailscale.com/docs/features/exit-nodes

## 2026-09-24 resumed preflight — live policy unchanged

Operator reauthenticated SSH check. Current iPhone100.117.55.81 is online and
not expired under the confirmed owner. Operator reported exit public IP91.98.112.14,
matching the TU1NZ main server. The explicit iPhone tu1nz.com HTTPS/DNS baseline
confirmation is still pending; no post-change client test has occurred.
Hetzner console was reopened after expiration; live whoami=chatops and
hostname=ubuntu-8gb-nbg1-2 confirmed. Console remains open.
Mac over Tailscale: Grafana3000/api/health, cAdvisor8080/healthz, Prometheus9090/-/ready
and NodeExporter9100/metrics returned200. Prometheus reports both scrape targets up
with empty lastError. Protected spicymila_bot retains its existing unhealthy state.

Remote control-main is now49294ce432ed59f03b7d75f651bd096106bd7286. Six changed
files since7c634d3 cover S11.2 canary provenance, migrations and optional evidence;
no network-hardening files overlap. Objects fetched without updating FETCH_HEAD
or switching the canonical checkout. Integration remains pending before activation.

Prepared candidate v2 preserves grants and SSH check exactly, adding IPv6 network
tests and denying server administration from the other Mac and iPhones.
The unsaved editor's user preview displays the intended autogroup:internet rule;
it is not evidence of all regression tests passing. Server-side test validation
remains mandatory before activation. A slow simulated typing attempt timed out;
its partial unsaved draft was discarded. Atomic paste then displayed the complete
draft. That draft was also discarded: Save/Discard disabled and original wildcard
rule restored in preview. No Save action, live-policy change or service change.

Private versioned artifacts and rollback copies: /opt/tu1nz_repos/network-hardening-private-2026-09-22/phase5-preflight-20260924T162249Z
Directory0700/files0600, SHA256SUMS all passed. v2 is not an activated policy.
Further gates: iPhone HTTPS baseline, final upstream integration and documentation
push, full policy test results and armed independent rollback, then controlled
activation with immediate fresh SSH/monitoring and iPhone exit/DNS/HTTPS retests.

## Phase5 activation gate — 2026-09-24

Operator confirmed iPhone HTTPS success through the main-server exit node and
public IP91.98.112.14. Fresh read-only preflight at16:25:23UTC passed both chatops
SSH ports, explicit root/nobody/daemon denial, four monitoring HTTP endpoints,
public website, node/cAdvisor scrapes, three service results and Tailscale health.
Container/listener/provider baseline captured for exact post-comparison.
Remote control-main49294ce integrated without conflict in merge375026d; canonical
checkout untouched. New bundle verifies and permits isolated worktree recovery.

Actual candidate: candidate-check-v2.json, SHA256 5db8ddf0fd796474de56ecb5438d3e2e5012da73fbe411f060248e0cdaeb7119
Private transaction directory:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/phase5-activation-20260924T162425Z/
External rollback and checker:
/Users/daniel/.codex/tu1nz-recovery/phase5-20260924T162425Z/
Original full policy SHA256 remains5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180.

Activation changes only network grants and adds regression assertions. Existing
owner/chatops SSH check is preserved. Built-in Tailscale validation runs as part
of Save and must reject a candidate with failed tests before persistence; absence
of an editor error alone is not treated as a test pass. Record actual UI outcome.
Use the independent authenticated Tailscale admin page for immediate full-policy
restoration on failure. Recovery webconsole and held SSH channel remain open.
No unattended timer/API rollback is available for Tailnet; rollback is externally
executable and supervised by the active agent through the admin console, independent
of the server network. Never claim a server-side firewall watchdog covers Tailnet.
If the admin path becomes unavailable, do not activate. On a failed check stop
the transaction and restore full original policy; verify editor readback and
repeat preflight. Original is byte-identical on server and Mac; restore keeps
owner/chatops restrictions and check, not the historical root-enabled policy.

Run scripts/tu1nz_phase5_readonly_check.py after and stable on the Mac, sequentially,
with at least60seconds of stable scrapes. Request immediate iPhone exit-IP and HTTPS
retest after applying. Do not declare completion without that client result.
No check-to-accept change in this activation. No provider/local firewall/service
changes. No protected container or bot test message.
