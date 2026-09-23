# TU1NZ network hardening — 2026-09-22

## Scope and current state
SSH documentation PR #177 merged into control-main at
333352f59b25a4b7475d5937808f387223dcb58b; all 110 CI steps passed.
This separate branch is security/network-hardening-2026-09-22.
The canonical detached checkout remains at 0390861869c0c54acc400a9e05481f7c847619e2.
Tailscale SSH is restricted to the confirmed owner identity and chatops, with
check and autogroup:self unchanged. General network allow-all is still active.
Public OpenSSH/2222 remains locally blocked. No public connection test is used.
The loaded Fail2ban sshd/nftables action targets ssh/22 instead of 2222.
Its Tailscale ignore network 100.64.0.0/10 must remain unchanged.

## Protected backups
Base: /opt/tu1nz_repos/network-hardening-private-2026-09-22/
Current Tailnet policy, separate rollback-tailnet.hujson, and Hetzner rules were
captured at 20260922T182832Z. The current policy hash is
5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180.
Privileged inventory: privileged-20260922T184509Z/
Includes live nftables, iptables/ip6tables, UFW, effective sshd configuration,
socket/listener state, loaded Fail2ban state and configuration archive.
Every capture succeeded. Archive/file SHA-256 checks passed again.
Directories are 0700, protected files 0600; backups remain outside Git.
The Hetzner text export records actual source networks; its JSON serialization
must be checked before using it as a provider restore payload.
Do not reuse the earlier pre-SSH-hardening policy, which would reallow root.

## Corrected strict offline comparison
Initial assertion incorrectly expected only the action's port property to
change. Fail2ban expands that port into actionstart and actionflush too.
scripts/tu1nz_fail2ban_port_preflight.py now constructs one exact expected dump:
only sshd/nftables port ssh -> 2222 and exactly one literal port expansion in
each of actionstart/actionflush. All other commands, values and order must match.
Missing/duplicate actions/properties and unexpected original templates fail.
No command from the dump is executed.

Tests at 20260922T184932Z:
- Three unittest methods passed, including 11 mutated-candidate negatives and
  three malformed/ambiguous-baseline negatives.
- The actual generated candidate dump passed.
- Three mutations of the actual dump were rejected.
- Offline candidate override backed up, removed, and all 184 original regular
  files compared byte-for-byte and by exact file set with the archived originals.
- Offline private modes were checked as 0700 directories/0600 files.
  Original source ownership/modes are preserved as archive metadata; the
  unprivileged offline copy intentionally retains restrictive backup modes.
- Offline copy remains rolled back, with no candidate override.
Evidence: strict-preflight-result-20260922T184932Z.json.
Candidate SHA-256: 2efa5b3d9dcf9bb4f9212eddb86a22a4db2625f69d76f54b55052be8e7eda4ec.

## Authorized Phase 3 activation and rollback
Create only /etc/fail2ban/jail.d/99-tu1nz-sshd-port.local:
[sshd]
port = 2222

A .local override loads after jail.local and packaged .conf files.
Before creation verify the complete live Fail2ban file set/content has not
drifted from the archive and the loaded action still targets ssh.
Capture a fresh full Fail2ban archive, loaded state and absence marker, with
UTC timestamp and SHA-256. Create exclusively; never overwrite an existing path.
Test configuration, then reload only sshd with fail2ban-client reload sshd.
Require port 2222 and unchanged loaded ignore/filter/timing/action/banned state.
Validate both generated nftables action templates and capture live rules.
No synthetic ban, firewall flush, SSH restart or provider/policy write.

Keep the original Tailscale SSH session open. The privileged process remains
open for up to 600 seconds awaiting independent Mac tests. Test fresh chatops
connections on Tailscale ports 22 and 2222 with strict known-host checks.
Require explicit Tailscale rejection for root/nobody/daemon.
Only after successful tests write MAC_TESTS_PASSED.json in the protected
phase3 timestamp directory. Verify COMPLETE.json afterwards.
On any failure write ROLLBACK there; missing confirmation also triggers rollback.
Rollback backs up and removes only the unchanged new override, syntax-checks
the original configuration, reloads sshd jail, and verifies port ssh.
The offline removal/restore was tested; live reload rollback has not yet run.
A changed target file causes a stop rather than overwriting another actor.
Privileged execution requires the operator's own terminal because its sudo
credential cache is not shared with the agent's SSH session.

## Later phases, not activated by this document
Hetzner minimization requires a verified independent console/recovery route,
complete listener/reverse-proxy/container dependency inventory, valid complete
provider rollback payload, and successful service tests before/after.
Tailnet allow-all replacement requires a complete actual connection matrix and
an available iPhone/Exit-Node test. Expired devices are not functional evidence.
Neither later phase is cleared for activation by the Fail2ban preflight.
Document and push each later exact change and rollback before activation.

## Exact privileged transaction implementation
The protected apply-phase3.py is byte-identical to the following source.
It is executed only after this document and the checker/tests are pushed.

```python
#!/usr/bin/env python3
"""Authorized Phase 3 only. Requires root; automatically rolls back unless verified."""
import ast,datetime,hashlib,json,os,pathlib,pwd,subprocess,tarfile,time
BASE=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')
TARGET=pathlib.Path('/etc/fail2ban/jail.d/99-tu1nz-sshd-port.local')
PAYLOAD=b'[sshd]\nport = 2222\n'
assert os.geteuid()==0
assert not TARGET.exists() and not TARGET.is_symlink()
uid=pwd.getpwnam('chatops').pw_uid
gid=pwd.getpwnam('chatops').pw_gid
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
OUT=BASE/('phase3-'+stamp)
OUT.mkdir(mode=0o700);os.chmod(OUT,0o700);os.chown(OUT,uid,gid)
def put(name,data):
 p=OUT/name
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data)
 os.chmod(p,0o600);os.chown(p,uid,gid)
def run(*cmd):
 r=subprocess.run(cmd,capture_output=True,check=True)
 return r.stdout
def state():
 return {k:run('fail2ban-client','get','sshd',k).decode()
  for k in ['ignoreip','journalmatch','maxretry','findtime','bantime','failregex','ignoreregex','actions','banned']}
# Compare full current Fail2ban file set and content with the protected original.
with tarfile.open(BASE/'privileged-20260922T184509Z/configuration-backup.tar.gz') as t:
 expected={m.name:t.extractfile(m).read() for m in t.getmembers()
           if m.isfile() and m.name.startswith('etc/fail2ban/')}
actual={str(p).lstrip('/'):p.read_bytes() for p in pathlib.Path('/etc/fail2ban').rglob('*') if p.is_file()}
assert actual==expected, 'Fail2ban configuration drift; no activation'
assert run('fail2ban-client','get','sshd','action','nftables','port').strip()==b'ssh'
before=state()
assert '100.64.0.0/10' in before['ignoreip']
put('before.json',json.dumps(before,indent=2).encode())
put('target-before.txt',b'ABSENT\n')
archive=OUT/'fail2ban-before.tar.gz'
fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:
 with tarfile.open(fileobj=f,mode='w:gz') as t:t.add('/etc/fail2ban',arcname='etc/fail2ban')
os.chmod(archive,0o600);os.chown(archive,uid,gid)
put('backup.sha256',(hashlib.sha256(archive.read_bytes()).hexdigest()+'  fail2ban-before.tar.gz\n').encode())
changed=False
try:
 fd=os.open(TARGET,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 changed=True
 with os.fdopen(fd,'wb') as f:f.write(PAYLOAD)
 os.chmod(TARGET,0o644)
 put('syntax-test.txt',run('fail2ban-client','-t'))
 put('reload.txt',run('fail2ban-client','reload','sshd'))
 assert run('fail2ban-client','get','sshd','action','nftables','port').strip()==b'2222'
 after=state()
 assert after==before, 'Unexpected loaded jail state change'
 put('after.json',json.dumps(after,indent=2).encode())
 put('jail-status.txt',run('fail2ban-client','status','sshd'))
 for prop in ['actionstart','actionflush']:
  s=run('fail2ban-client','get','sshd','action','nftables',prop)
  assert b"echo '2222'" in s and b"echo 'ssh'" not in s
  put(prop+'.txt',s)
 put('nft-after.txt',run('nft','-a','list','ruleset'))
 put('WAITING_FOR_MAC_TESTS.json',json.dumps({'utc':stamp,'port':2222,'timeout_seconds':600}).encode())
 print('WAITING_FOR_MAC_TESTS',OUT,flush=True)
 print('Dieses Terminal offen lassen. Codex prueft jetzt beide SSH-Verbindungen.',flush=True)
 deadline=time.monotonic()+600
 while time.monotonic()<deadline:
  if (OUT/'ROLLBACK').exists():raise RuntimeError('Explicit rollback requested')
  ack=OUT/'MAC_TESTS_PASSED.json'
  if ack.exists():
   assert not ack.is_symlink()
   result=json.loads(ack.read_text())
   assert result.get('chatops_22') is True and result.get('chatops_2222') is True
   assert result.get('forbidden_users_denied') is True
   assert TARGET.read_bytes()==PAYLOAD
   put('COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'port':2222,'mac_tests':result}).encode())
   print('PHASE3_COMPLETE',flush=True)
   break
  time.sleep(2)
 else:raise TimeoutError('No confirmed Mac tests within 600 seconds')
except BaseException:
 if changed:
  assert TARGET.read_bytes()==PAYLOAD, 'Unexpected target drift; do not overwrite'
  put('override-before-rollback.local',TARGET.read_bytes())
  TARGET.unlink()
  run('fail2ban-client','-t')
  run('fail2ban-client','reload','sshd')
  assert run('fail2ban-client','get','sshd','action','nftables','port').strip()==b'ssh'
  put('ROLLED_BACK.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'port':'ssh','target':'absent'}).encode())
  print('PHASE3_ROLLED_BACK',flush=True)
 raise
```

## Phase 3 completed
Preparation/checker commit 058425b83eb1acacbaf6e7f3f0d123d3ce0f6ab8 was pushed
before activation. The operator started the documented privileged transaction.
Fresh backup and evidence: phase3-20260922T185354Z/ under the private base above.
The exact local override was created root-owned with mode 0644; configuration
syntax passed and only the sshd jail was reloaded successfully.
Loaded nftables action port is 2222; actionstart/actionflush target 2222.
Loaded filters, ignore networks, timing, actions and banned-IP list matched
the pre-activation snapshot. Jail active, zero failures and zero bans.
Independent Mac tests at 2026-09-22T18:54:35Z: chatops on 22 and 2222 exited 0;
root/nobody/daemon on Tailscale SSH exited 255 with explicit policy rejection.
Strict host-key checks used throughout. No public connection test performed.
Backup hash and protected file modes passed; transaction completion recorded at
2026-09-22T18:54:35.786264+00:00. Its temporary rollback wait has now ended.
Fail2ban, tailscaled, ssh, nginx and docker are active. Canonical checkout clean
and still detached at 0390861869c0c54acc400a9e05481f7c847619e2.
No UFW, OpenSSH, Hetzner or Tailnet policy changes occurred in Phase 3.
No forced ban was used; validation covers configured/loaded action templates,
not an induced attack or packet-level ban test.

Post-completion rollback, if required: in a privileged operator terminal,
first back up and verify the exact new override has not changed; remove only
/etc/fail2ban/jail.d/99-tu1nz-sshd-port.local, run fail2ban-client -t, then
fail2ban-client reload sshd. Verify loaded nftables action port is ssh, all
original jail settings match before.json, and independently retest both SSH
paths. Do not restore the whole archive over unrelated changes.

## Phase 4 entry gate: paused before any provider change
Provider firewall 10043301 remains attached to server 109772243, with inbound
TCP 80-8080, TCP 22, TCP 443 and ICMP from 0.0.0.0/0 and ::/0.
No provider mutation has occurred. An independent authenticated Hetzner console
or recovery route has not been established in this task.
Read-only Docker inventory found host-published Grafana 3000 and cAdvisor 8080
inside the broad provider interval. External monitoring/consumer requirements
for these direct ports are unresolved; their removal is not yet authorized by
a complete dependency matrix. Prometheus is published on 9090; bot ports are
8081 and 8090, outside the current provider TCP range. n8n and Jellyfin bind
localhost 5678 and 8096 respectively.
Read-only enabled nginx directives show public 80/443 routes for API, lighting,
n8n, trendwatch and WantMeSeen domains, with local upstreams including 8090,
8081, 5678 and 3011. This is a partial routing inventory, not nginx -T or proof
that every upstream currently works. No public endpoint test was performed.
Docker reports spicymila_bot Up 3 days (unhealthy), a pre-existing health issue
rather than a demonstrated result of the Fail2ban change. Do not claim a green
whole-server baseline or repair unrelated applications under this task.
Phase 4 remains NO-GO pending verified independent console, resolved monitoring
port dependencies and an adequate service baseline. Phase 5 is not activated;
general Tailnet allow-all and hardened owner/chatops SSH rule remain unchanged.
The previously observed expired iPhone entries require renewed verification
and an actual iPhone/Exit-Node test before removing allow-all.
No overall-completion merge has been attempted; the security branch remains
separate from control-main. Phase 3 result commit: 552a047905045a51203845468fbb9b12eba80401.

## Independent console verified; Phase 4 health preflight failed
On 2026-09-22 the operator-authorized browser workflow opened project Default,
server 109772243 and its independent Hetzner web console. Existing local login
was already active. Actual console commands returned whoami=chatops and
hostname=ubuntu-8gb-nbg1-2. No credential was requested, read or entered.
The console is retained open as the recovery path. No root login was used.

Fresh origin/control-main is cedd7ec6648deeaec1468b809e42596c37bd5000.
Since 333352f it includes 7fd88ec and merge PR #176: S11.2-R12 Telegram health
child contract, 10 changed files. These changes were fetched/read only; no
merge/rebase or canonical-checkout update occurred.

Read-only monitoring/container investigation:
- Grafana host port 3000 and cAdvisor host port 8080 are published on all IPv4
  interfaces by Docker; both use monitoring_default bridge networking.
- Prometheus also uses that bridge, with host publication 9090 and a bind-mounted
  /tausendunde1nz/05_it_security/monitoring/prometheus.yml.
- Both the file and the actually loaded target API use localhost:8080 for
  cAdvisor and localhost:9100 for node_exporter. Actual target API reports both
  DOWN / connection refused, with scrapes observed around 19:01 UTC.
  In a bridge-networked Prometheus container localhost refers to that container;
  this explains the mismatch with separately running exporter services.
- Host-local HTTP requests to 3000/api/health, 8080/healthz and 8090/health each
  returned 200. These are local checks, not public reachability tests.
- spicymila_bot remains unhealthy with curl healthcheck exit 7. Configured
  healthcheck URL is http://127.0.0.1:8090/health inside the container, whereas
  Docker publishes host 8090 to container 8080. This is a likely incorrect
  healthcheck port; no container/configuration repair was performed.
- External direct-client need for Grafana 3000 and cAdvisor 8080 remains
  unproven. Partial reference search cannot establish absence of consumers.

The required monitoring preflight failed, so Phase 4 stopped before any provider
rule mutation. Fixing monitoring target addresses or bot healthcheck is outside
the currently authorized port-only Fail2ban/provider/Tailnet hardening scope.
Do not silently incorporate those repairs. Require a separately authorized,
backed-up and documented correction followed by a green monitoring baseline,
and resolve external port consumers before removing the broad provider rule.
Phase 5 remains unactivated; iPhone/Exit-Node functional validation still needed.
Fail2ban Phase 3 remains successfully completed; no new evidence attributes these
pre-existing container/loopback failures to its restricted port correction.

## Authorized monitoring correction: read-only preflight stopped
The operator authorized a narrowly scoped monitoring correction but explicitly
froze all MyChatBuddy/RC4/legacy containers through 2026-09-24 and required an
immediate stop on any failed internal test. No live correction was activated.

Confirmed Compose source: /tausendunde1nz/05_it_security/monitoring/docker-compose.yml.
Prometheus (service prometheus, PID 2432) runs on monitoring_default bridge,
IP 172.29.0.4, aliases prometheus and tu1nz_prometheus. Its command loads the
bind-mounted /etc/prometheus/prometheus.yml; no lifecycle HTTP flag is enabled.
cAdvisor (service cadvisor, PID 2466) uses the same bridge, IP 172.29.0.2,
aliases cadvisor and tu1nz_cadvisor, internal port 8080. Grafana is 172.29.0.3,
service grafana, internal/host port 3000. Node Exporter (service node_exporter,
PID 2430) uses network_mode=host and pid=host; it has no bridge DNS alias or
container IP. The inspected monitoring bridge gateway is 172.29.0.1.
All four monitoring containers have restart count zero and started 2025-11-01.
The persisted Prometheus configuration literally targets localhost:9100 and
localhost:8080. In its bridge network this is Prometheus's own network namespace,
not either exporter. The historical author/reason for those values is unknown.

Sequential internal read-only tests from the existing Prometheus container,
using its existing /bin/wget and discarding metrics output:
- http://cadvisor:8080/metrics: exit 0.
- http://172.29.0.1:9100/metrics: exit 1, download timed out after five seconds.
The gateway came from docker network inspect, not a guessed address.
The timeout blocks adoption of this Node Exporter target. Its cause is not yet
proven; do not label it definitively as firewall filtering. No alternative
address, network mutation or partial cAdvisor-only correction was activated.
No public connection was tested and no exporter data was printed.

spicymila_bot is the unhealthy container, service/project spicymila_bot from
/opt/spicymila_bot/docker-compose.yml. It started 2026-09-19T08:22:54Z and has
restart count zero. Host 8090 forwards to container 8080; its Docker healthcheck
runs curl against 127.0.0.1:8090 inside that container, which is the wrong
namespace for the host-port mapping. The enabled nginx configuration for
api.mychatbuddy.dev sends /spicy and /spicymila health/webhook routes to host8090.
This proves a MyChatBuddy service relationship, though membership in the exact
72-hour cohort was not independently documented. Treat it as protected and
defer all healthcheck/container correction until the observation ends.
api-mychatbuddy is a separate healthy container on proxy network, restart count
zero; it was not altered. No protected container was exec'd, restarted, recreated
or otherwise mutated. No provider lease, cost setting or port publication changed.

Current remote control-main remains cedd7ec6648deeaec1468b809e42596c37bd5000.
It was fetched read-only; no history rewrite or canonical checkout change.
No branch integration or monitoring activation is claimed. A non-rewriting
integration and renewed conflict checks remain prerequisites before activation.

Immediate stop follows the failed internal test. Prometheus targets, Compose,
healthchecks, systemd, Hetzner and Tailnet remain unchanged. Existing Fail2ban
2222 correction is retained. Further target-route diagnosis and a tested safe
Node Exporter route are needed before monitoring correction can proceed.
Port-consumer/log inventory and stable post-correction observation remain
incomplete; Phase 4 is not cleared. No live-change backups/rollback are claimed
for a correction that never proceeded beyond read-only preflight.


## Live Docs pipeline completed — 2026-09-23T18:12:57Z
Preparation commit aa66bfc7f23ccc31e732d79988a9d79dc0bd306a was pushed before
activation. Privileged transaction docs-transaction-20260923T181203Z completed
with COMPLETE.json at18:12:57.570435Z. Fresh originals, metadata, executable
rollback, offline proof and validation acknowledgment are in the private base:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/docs-transaction-20260923T181203Z/

Effective WorkingDirectory is /opt/tu1nz_repos/docs, user/group chatops.
The safe systemd run at18:12:05-18:12:06Z exited0 with Result=success and staged
one valid PDF. Docs local and remote HEAD remained4644acf and worktree remained
clean before explicit publication: no automatic commit or push occurred.
All PDF checks passed again, extracted content matched the strict allowlist,
and the actual live page was rendered and visually inspected without clipping.
Stage: /opt/tu1nz_repos/doc-staging/stage-20260923T181205Z-juhvnebs/
PDF SHA256:34248f56c3f67fbe1a665f21fdee7f6ca0baf8de2bd8eca9a08a5f17323f7fd2.
Only after this review was explicit publish invoked as chatops with that hash.
Docs commit537aa8fd69d755c641246cc1b507c69b3e1cd5f5 contains only
System_Dokumentation_Tausendunde1nz_2026-09-23.pdf. Push to Docs main and exact
remote HEAD verified; worktree clean. Timer remains active, next run22:00UTC,
and now performs staging only. The in-process rollback wait has completed.
For later configuration rollback use the captured rollback.py --rollback with
its transaction directory, after checking drift; this does not erase published
Git history or rewrite historical systemd timestamps.

## Phase4 resumed: no activation yet
Fresh provider read still shows original TCP80-8080, TCP22, TCP443 and ICMP,
attached to the same server. No provider mutation occurred.
External Mac preflight: n8n.mychatbuddy.dev and lighting.tu1nz.com DNS both resolve
to91.98.112.14; HTTP301 redirects to corresponding HTTPS; HTTPS200 with normal
certificate validation. These external tests are authorized by the latest order.
Backup latest run completed03:34:56UTC with Result=success. The doc service is
no longer in systemctl --failed; protected pre-existing private-alpha failure
and spicymila_bot unhealthy state remain, untouched. No bot message was sent.
One enabled nginx config (tu1nz.conf) is not readable as chatops, so the complete
current routing inventory still needs a privileged read. Do not claim it passed.
control-main remote is now7c634d3b82572e8459d51c69f04dce82c624d766; upstream
integration/dependency review remains outstanding. Canonical checkout untouched.
The previously opened recovery tab was absent; reopening its known console URL
succeeded, but Chrome then blocked automation because another extension UI was
open. Recovery login/session could not be freshly verified. Provider activation
is gated on restoring that independent recovery access and remaining preflight.
Phase5 remains unactivated. No additional security change or merge performed.


## Activation attempt rolled back — 2026-09-23
Preparation commit6744d70 was pushed before activation. The transaction's offline
success and injected-monitoring-failure paths were executed with a mocked provider;
the latter restored the exact original array. No live rollback was used in that test.
The actual provider reduction then succeeded and entered external validation.
The original rules were automatically restored at2026-09-23T18:28:45.523926Z.
Fresh hcloud describe equals the complete original-firewall.json including rules
and attachment. New chatops Tailscale SSH passed after rollback. Node/cAdvisor
remain up with no scrape error. No server/container configuration was changed.

Cause: external checker ran under macOS Python3.9, where socket.timeout is not
necessarily the built-in TimeoutError used in its exception test. The first new
public TCP22 attempt timed out (expected blocking), but was incorrectly re-raised.
Its exception handler requested rollback immediately; the server guard restored
and readback-verified originals. This is a validation-tool defect, not evidence
that a protected port accepted a connection or that websites/SSH failed.
All ten preceding HTTP/HTTPS assertions and both chatops plus three forbidden-user
SSH assertions had passed. The remaining public port matrix did not complete;
no successful final Phase4 validation or IPv6 blocking result is claimed.
The broad original provider rule is therefore active again, including3000/8080.

Corrected versioned checker scripts/tu1nz_public_port_check.py handles both
socket.timeout and TimeoutError explicitly, plus ETIMEDOUT/ECONNREFUSED. No-route
is inconclusive and cannot satisfy success; successful connect fails; unrelated
errors propagate; only the exact two addresses/six ports are accepted. Six offline
tests passed on the actual Mac Python3.9 runtime. Missing/duplicate result sets
fail, so the checks were not broadly relaxed. It was not used to reactivate rules.
Local reviewed checker copy is beside the external backup. A fresh backup/diff
and a complete repeated transactional validation remain required. No Phase5 action.

Evidence and recovery remain in
/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-20260923T182627Z/
including apply output, after-firewall, container baseline, explicit rollback
request, rollback output and ROLLED_BACK.json. Independent Mac backup remains
/Users/daniel/.codex/tu1nz-recovery/20260923T182627Z/.
Docs pipeline correction and its published PDF remain successfully completed.

## Verified Phase 4 completion — 2026-09-23 19:12:01 UTC

Second transaction completed successfully; external Mac report and server COMPLETE agree.
Preparation commits: 319fbfa, fe5a651 and 985f051; earlier timeout correction ffce37d.
Live firewall 10043301 on server 109772243 now permits inbound TCP 80, TCP 443 and
ICMP from IPv4/IPv6 only. No outbound rule, UDP grant or Tailnet change was added.
TCP 80 is required for the verified HTTP-to-HTTPS redirects. UDP 41641 was not
previously explicitly allowed by Hetzner and a new grant was not necessary for
the verified Tailscale connectivity. Existing local UDP allowance is unchanged.

All twelve required negative public tests passed: 22,2222,3000,8080,8090,9100
on both public IP families returned BLOCKED_TIMEOUT, with successful TCP443
positive controls. Additional 5432/5678 probes passed in both families. Exact
provider rule readback proves the old broad range is absent; no exhaustive scan
of every port is claimed. Five domains passed DNS/HTTP/HTTPS and content checks;
wantmeseen.de retains its expected 308 redirect, other HTTPS pages returned 200.
Fresh independent chatops SSH connections on Tailscale22 and OpenSSH2222 passed.
Tailscale SSH rejected root, nobody and daemon explicitly (exit255).
Privileged PRE/POST: filter INPUT DROP for IPv4/IPv6, Fail2ban2222,
chatops-only OpenSSH, identical listener bindings and identical nftables rules
apart from counters/handles/metainfo. Docs, health and encrypted-backup service
results remained success. Tailscale Running, no Health errors; exit-node capability
remained enabled. An actual iPhone exit-node client test remains pending.

Fifteen monitoring samples span fresh scrapes 19:10:42–19:11:58 UTC; cAdvisor and
Node Exporter remained up with empty lastError. All captured container IDs,
start times, restart counts, health, bindings and networks remained unchanged.
The pre-existing spicymila_bot health defect was preserved, not repaired. No bot
message, protected-container restart, cost/lease change or provider lease action
was performed. This validates observed runtime stability, not a new billing audit.

Server evidence and rollback:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-retry-20260923T185834Z/
External copy/report:
/Users/daniel/.codex/tu1nz-recovery/20260923T185834Z/EXTERNAL_COMPLETE.json
Privileged evidence: phase4-privileged-20260923T190741Z and
phase4-privileged-20260923T191128Z under the private base directory.
Both automatic guards completed after validation. Rollback remains available via
recovery console as chatops using hcloud firewall replace-rules 10043301 with the
retry directory's rollback-rules.json; verify exact original readback, then repeat
website, DNS, SSH and monitoring checks. This intentionally restores the old broad
rules and must only be used for a demonstrated regression. Local firewall/SSH and
Tailnet must not be rolled back as part of that provider-only restoration.

Phase5 is prepared separately, NOT activated. See TAILNET_PHASE5_PREPARATION_2026-09-23.md.
