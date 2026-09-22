# TU1NZ limited Tailscale SSH hardening — 2026-09-22

Status: ACTIVATED AND VERIFIED. The authorized exact two-field restriction is
active. A documentation-lint rollback and successful reactivation are recorded.

## Scope
Server ubuntu-8gb-nbg1-2 / 100.121.130.51; MacBook 100.98.95.69; account chatops.
The exact confirmed identity is in the protected candidate, not in Git.
Identity UTF-8 SHA-256: e3438f352e0b613914fc349f0d7558b144a95dd3ef79f6bc8abb284336a6040e.
No additional ED25519 access is being configured.
Preserve action check and destination autogroup:self. Do not change the general
allow-all grants rule, OpenSSH/2222, UFW/nftables, Hetzner, Fail2ban, sudo, device
ownership, keys, services or existing canonical checkout.

## Confirmed baseline
- Tailscale SSH RunSSH=true; independent noninteractive chatops login succeeded.
  Authentication method none is expected for Tailscale SSH.
- Existing known host matched SHA256:zXg9LZbOago+z9c+9no+uNN0EVr4I6/pG7q9xsDPSjo.
- Operator privileged evidence at 2026-09-22 17:59 UTC: active IPv4/IPv6 INPUT
  DROP, UFW kernel rules present; no public TCP/2222 accept or DNAT path.
  New public TCP/2222 is dropped; established/related traffic is separate.
  No external connection test performed.
- IPv4 tailscale0 ingress is accepted by ts-input before UFW.
- Hetzner firewall 10043301 attached to server 109772243 permits TCP 80-8080,
  including 2222. Local firewall is the current effective public block.
- OpenSSH and systemd socket listen on 0.0.0.0:2222 and [::]:2222.
  Effective inspected context: AllowUsers chatops, PermitRootLogin no,
  PubkeyAuthentication yes, password/keyboard-interactive/hostbased/Kerberos/
  GSSAPI off. TCP/agent/X11 forwarding off; Unix socket forwarding remains.
- Loaded Fail2ban sshd action nftables targets service ssh = TCP 22, NOT 2222.
  Zero bans; Tailscale 100.64.0.0/10 ignored. Record only; no remediation.
- Existing chatops sudo/docker and broad individual NOPASSWD tool privileges
  remain. Direct root-login exclusion is not least-privilege remediation.
- iPhones/secondary Mac included pre-existing expired entries. Their actual
  operation is not established by policy-only checks.
- Auto-recovery required services: fail2ban.service, trendwatch2-fetch.service.
  No direct 2222 dependency in inspected backup/guard/recovery scripts.
  Indirect and external dependencies have not been fully excluded.

## Git isolation and authorization
Canonical /opt/tu1nz_repos/control remains detached, clean, HEAD
0390861869c0c54acc400a9e05481f7c847619e2.
Reflog proves commit checkouts; actor is not established.
Remote default branch main differs from Control integration branch control-main.
Fresh confirmed remote base: c084d5fad508aa11574c31d728e82362117932f0.
Worktree: /opt/tu1nz_repos/worktrees/ssh-access-audit-2026-09-22
Branch: docs/ssh-access-audit-2026-09-22.
Commit only this document. Push only this branch; no merge.
Linked-worktree creation/base fetch update shared Git metadata, not canonical
HEAD or working files.

## Approved exact semantic diff
Original: action=check; src=[autogroup:member]; dst=[autogroup:self];
users=[autogroup:nonroot, root].
Replace only src with the single confirmed owner and users with [chatops].
The exact full candidate preserving original comments/formatting is:
/opt/tu1nz_repos/ssh-access-audit-private-2026-09-22/policy-candidate.hujson
Its source identity is bound by the hash above. Do not persist extra sshTests.

## Protected backup and complete rollback
Capture: 2026-09-22T18:09:23Z.
Original: /opt/tu1nz_repos/ssh-access-audit-private-2026-09-22/policy-original-20260922T180923Z.hujson
Separate rollback: /opt/tu1nz_repos/ssh-access-audit-private-2026-09-22/rollback-policy.hujson
Both SHA-256: f732d21e94ee9c09ca3c8a90d627ff26c0bf888de14e1e0364054777716e21cf
Manifest: /opt/tu1nz_repos/ssh-access-audit-private-2026-09-22/SHA256SUMS
Directory 0700; private files 0600; outside Git.
Git-before and service/network baseline are retained in the same directory.
Keep the existing SSH session and authenticated admin console open.
On activation/test failure restore the ENTIRE original policy in the JSON
editor, validate/save, then independently retest chatops from the Mac.
If not activated, discard the draft; the live original already remains intact.
On concurrent policy drift stop rather than overwrite others' changes.
Never invoke the unrelated OpenSSH rollback script or reset/restart services.
No policy rollback requires opening public ports or handling secrets.

## Risk and validation plan
autogroup:self still means the owner's devices. This phase does not constrain
to one physical Mac or only this server. Other owned-device SSH logins as
root/non-chatops will be removed. General network/Exit-Node grants stay identical.
check mode may demand periodic identity confirmation.
1. Commit/push this pre-activation document before activation.
2. Validate syntax and SSH evaluation: owner to target chatops check-allowed;
   root/nobody/daemon denied. Temporary assertions must not enter live policy.
3. Verify the draft contains only the approved diff and no concurrent drift.
4. Keep the original SSH session open; activate only after successful validation.
5. New independent Mac chatops connection: BatchMode, strict known-host checks,
   no agent forwarding or local-key authentication.
6. Negative root and existing nonroot tests execute only /usr/bin/false if
   unexpectedly admitted. Require explicit policy rejection. Timeout, check
   expiry or nonexistent account is not denial evidence.
7. Compare services/listeners/Tailscale settings/DNS with baseline. Inspect
   monitoring and backup last results without triggering work or notifications.
   Record unperformed iPhone/Exit-Node end-to-end tests explicitly.
8. Verify canonical HEAD and working files remain unchanged.
9. Back up this document before appending actual activation time, live-policy
   hash, test results and limitations. Commit/push the same branch.

## Execution results
Pre-activation documentation commit:
2230493a9b5308a71eb0c0810c8ed718b34cd73a, pushed and remote SHA verified
before any policy save.

### Server-side preflight
Tailscale's JSON editor was used with the exact candidate and temporary sshTests:
owner -> 100.121.130.51 must check chatops and deny root/nobody/daemon.
A second deliberately incompatible root-accept assertion prevented persistence.
The server rejected the entire draft, reporting only the control assertion:
ssh user root: want accept, got deny. No syntax or intended-test failure was
reported. This expected negative control was not an activation failure.
All temporary test fields were then removed. Editor content was compared
byte-for-byte with the protected exact candidate before activation.

### Activation and persistence
Activation observed between 2026-09-22T18:13:37Z and 18:13:50Z (UTC).
The UI confirmed Saved tailnet policy file; Save/Discard became disabled.
After a full reload, copied saved contents matched the exact candidate byte for
byte, with no sshTests field. Saved length: 2256 UTF-8 bytes.
Saved SHA-256:
5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180
Only SSH src and users changed; grants, action check and autogroup:self unchanged.
The first activation was rolled back after a documentation-only lint error;
see recovery record below.

### Independent post-save connection tests
At 2026-09-22T18:13:50Z, fresh MacBook SSH processes used ControlMaster=no,
ControlPath=none, BatchMode=yes, strict known-host checking, no password,
keyboard-interactive, public-key or forwarded-agent authentication.
- chatops: exit 0, id -un chatops, UID 1001, correct server hostname;
  authenticated with Tailscale method none.
- root: exit 255, explicit tailnet policy does not permit SSH as root.
- nobody: exit 255, explicit tailnet policy rejection.
- daemon: exit 255, explicit tailnet policy rejection.
nobody and daemon were independently confirmed to exist locally before testing.
No root or other forbidden-user session was established. The harmless fallback
command /usr/bin/false was not reached. Known-host key matched in all tests.
The original held SSH session was retained throughout the transaction.

### Post-change baseline comparison
All comparison checks passed:
- monitored service and timer ActiveState/SubState unchanged;
- TCP listener bindings unchanged, including OpenSSH port 2222;
- Tailscale RunSSH, WantRunning and Exit-Node advertised routes unchanged;
  routes remain 0.0.0.0/0 and ::/0;
- tailnet DNS resolved to the confirmed server; public DNS resolution succeeded;
- canonical checkout HEAD unchanged and git status clean.
Health service finished successfully after activation at 18:14:05Z.
Latest encrypted backup completed successfully at 03:37:49Z; autorecovery last
result success at 18:10:38Z; security audit success at 07:00:01Z.
No job was manually triggered. Full post-activation backup/restore and iPhone/
Exit-Node end-to-end traffic tests were not performed. Their configuration and
relevant running services were preserved; do not overstate functional coverage.

### Remaining issues, outside approved scope
Fail2ban targets TCP 22 instead of OpenSSH 2222. Public OpenSSH bindings and the
broad Hetzner rule remain, with active local filtering. General network allow-all
and existing chatops sudo/docker rights remain. check mode can require future
identity confirmation. The SSH rule remains owner-device scoped, not a unique
Mac/server pair. Expired device entries remain. No merge or canonical checkout
deployment was performed.


## Documentation-format recovery and reactivation plan
git diff --cached --check rejected a new blank line at EOF before the final
documentation commit. No runtime test failed. Following the operator's literal
rollback instruction, the entire original policy was restored through the UI.
An independent chatops login succeeded at 2026-09-22T18:15:38Z.
The only correction is normalized Markdown trailing whitespace/final newline.
The exact previously validated candidate and its hash remain unchanged.
Push this recovery record before reapplying that same candidate. Repeat fresh
positive/negative SSH and baseline checks, then append final evidence.

## Final completion after reactivation
Recovery/pre-reactivation documentation commit:
df3a868b8801993bb3ca431d652333044ed2f8d0, pushed before reactivation.

Final save confirmation: 2026-09-22T18:16:08.840Z (client-observed UTC).
Fresh independent SSH tests at 2026-09-22T18:16:20Z:
chatops exit 0 / UID 1001; root, nobody and daemon each exit 255 with explicit
Tailscale policy denial. The held original SSH session remains open.
After reload, the actual saved editor text exactly matched the 2256-byte
candidate with SHA-256 5c6db5289fbbc0d7131d70f54a7dab516245b58d0da86e6ec3a1002deb394180.
A first clipboard read selected page text rather than the editor; it was
discarded as invalid evidence. Correct editor-focus comparison passed.

Final baseline recheck: all monitored service/timer states, TCP listener
bindings and selected Tailscale/Exit-Node preferences identical to the
pre-activation baseline; tailnet and public DNS succeeded. Latest monitored
job results were successful. Canonical detached HEAD and clean status unchanged.
No network-wide grants, SSH/2222, firewall, Fail2ban, sudo or keys were changed.
No public connection test, restart, backup trigger or merge occurred.
The documentation-only formatting error was corrected and its required policy
rollback succeeded before this final reactivation. Protected full rollback
policy and per-edit documentation backups remain available.
All previous functional-coverage limitations and out-of-scope issues remain.
