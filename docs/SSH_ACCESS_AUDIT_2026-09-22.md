# TU1NZ limited Tailscale SSH hardening — 2026-09-22

Status: PRE-ACTIVATION. The operator authorized only the two-field SSH policy
change described below. Activation has not occurred at this commit.

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
Pending validation and activation.
