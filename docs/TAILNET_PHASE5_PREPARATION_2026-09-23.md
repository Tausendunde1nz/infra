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
