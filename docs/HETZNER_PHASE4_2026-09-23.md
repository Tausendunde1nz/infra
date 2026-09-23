# Phase4 exact provider reduction — prepared, not activated

## Confirmed preflight
Private privileged evidence phase4-privileged-20260923T182445Z passed SHA256.
Nginx routing and listeners confirm public web80/443; all app upstreams are local.
External Mac tests: n8n.mychatbuddy.dev, lighting.tu1nz.com, tu1nz.com and
wantmeseen.com HTTP301/HTTPS200; wantmeseen.de HTTP301/HTTPS308 to .com.
All tested DNS resolves91.98.112.14; TLS verified normally. Mac public route is
en0 via LAN gateway, not the Tailscale exit node. No bot endpoint/message tested.
Historic trendwatch upstream3011 is not asserted healthy or repaired here.
Kernel IPv4/IPv6 INPUT/FORWARD DROP remains. OpenSSH2222 allows only chatops,
no root/password/kbd-interactive authentication; Fail2ban loaded port2222.
Fresh independent SSH22/2222 as chatops passed; root/nobody/daemon explicit
Tailscale policy denials. Monitoring node/cAdvisor up with no lastError.
Protected unhealthy bot/private-alpha failure remain accepted existing baseline.
Backup completed03:34:56UTC success; health completed18:13:08UTC success.
Recovery console freshly confirmed whoami=chatops, hostname=ubuntu-8gb-nbg1-2.
Only firewall10043301 is attached to server109772243, status applied.
Provider rules are identical to the earlier protected capture.

## Exact diff (IPv4 0.0.0.0/0 and IPv6 ::/0)
- inbound TCP80-8080 -> TCP80
- remove inbound TCP22
- retain inbound TCP443 and ICMP unchanged
- no outbound rules, no added UDP rule, no other provider changes

Tailscaled listens UDP41641, and local UFW permits it, but the provider has never
had that explicit inbound rule. Current Tailscale is healthy with a direct peer
endpoint recorded. No need to expand provider UDP permission was established;
its existing stateful/outbound path is preserved. No unsupported port is added.
Tailscale/Exit-Node traffic uses the existing encrypted transport; general Tailnet
grants remain unchanged. Actual iPhone exit-node test remains unavailable:
both phone entries are offline/expired. Do not claim that end-to-end test passed.

## Exact backups and recovery
Server backup /opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-20260923T182627Z/
Mac copy /Users/daniel/.codex/tu1nz-recovery/20260923T182627Z/
Both contain original-firewall.json, rollback-rules.json, candidate-rules.json,
and verified SHA256SUMS; directories0700, files0600. JSON rollback equals original
rule array. Candidate validation admits exactly80,443,ICMP with original sources.
CLI array payload follows official example:
https://raw.githubusercontent.com/hetznercloud/cli/main/examples/firewall_rules.json
Provider stateful behavior and new-connection requirement:
https://docs.hetzner.com/cloud/firewalls/faq/

Independent recovery through the retained Hetzner console as chatops:
hcloud firewall replace-rules 10043301 --rules-file /opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-20260923T182627Z/rollback-rules.json
Then describe firewall and compare full rules/attachment to original-firewall.json.
If server CLI unavailable, use authenticated Hetzner UI to restore the four
recorded original rules from the protected Mac copy. No credential is in the backup.

## Transaction and validation
Versioned scripts/tu1nz_hetzner_phase4_transaction.py is copied identically as
transaction.py in the private backup. It verifies original provider state and
hashes, captures container IDs/start/restarts/health/ports/networks, then replaces
rules. It requires the exact candidate and unchanged attachment. It continuously
checks container equality and monitoring while waiting at most600seconds for
external validation. Error, signal, failed check or missing acknowledgment causes
exact original rules restoration and readback verification. No service restart,
local rule edit, bot exec or message. Abrupt SIGKILL/powerloss requires independent
recovery; provider API failure may likewise require manual console recovery.
No transaction attempts to promise protection against simultaneous foreign
provider writers; no such writer was observed. Do not run another rule edit.

External validation uses fresh connections: websites/redirects/TLS/DNS, chatops
SSH22/2222, forbidden accounts denied, six new public TCP probes to22/2222/3000/
8080/8090/9100. No payload sent on internal ports. IPv6 reachability is checked
where the Mac has a route; otherwise record that limit and use exact dual-stack
provider rules as configuration evidence. Recheck monitoring, health/backup,
Tailscale and unchanged containers before acknowledgment. Existing TCP sessions
can survive a provider update; only new probes demonstrate changed admission.
After success append actual evidence and push. Phase5 stays unactivated.
