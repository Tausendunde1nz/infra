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
