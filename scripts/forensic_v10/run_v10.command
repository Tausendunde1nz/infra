#!/bin/sh
# Exactly one future read-only root collection. No activation or watchdog.
exec /usr/bin/ssh -tt -F /dev/null -p 2222 -o HostKeyAlias=100.121.130.51 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no chatops@100.121.130.51 '/usr/bin/sudo /usr/bin/python3 -I -S -B -c '"'"'import hashlib,os,stat
p='"'"'"'"'"'"'"'"'/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27/scripts/forensic_v10/launcher_v10.py'"'"'"'"'"'"'"'"'
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_NOATIME)
with os.fdopen(fd,'"'"'"'"'"'"'"'"'rb'"'"'"'"'"'"'"'"') as f:
 if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise RuntimeError('"'"'"'"'"'"'"'"'launcher type'"'"'"'"'"'"'"'"')
 b=f.read(500001)
if hashlib.sha256(b).hexdigest()!='"'"'"'"'"'"'"'"'4a18a334f3560dfb2a91eabc8babd2d74a8873f2e82233aede8342e088eebf85'"'"'"'"'"'"'"'"': raise RuntimeError('"'"'"'"'"'"'"'"'launcher digest'"'"'"'"'"'"'"'"')
exec(compile(b,p,'"'"'"'"'"'"'"'"'exec'"'"'"'"'"'"'"'"',dont_inherit=True),{'"'"'"'"'"'"'"'"'__name__'"'"'"'"'"'"'"'"':'"'"'"'"'"'"'"'"'__main__'"'"'"'"'"'"'"'"','"'"'"'"'"'"'"'"'__file__'"'"'"'"'"'"'"'"':p})'"'"''
