#!/usr/bin/env python3
"""One read-only sudo call over the confirmed Tailscale IPv4 route. No activation."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import subprocess
import sys

READER_SHA = "651cf33d3607d0aae425bbd6dde28ba5a6e20ee4c3ba3e1317caa84d35e376ea"
BASE = Path('/Users/daniel/.codex/tu1nz-recovery/backup-notify-v3-20260927')
READER = BASE / 'tu1nz_backup_notify_reader_v3.py'
PREFIX = 'TU1NZ_BACKUP_NOTIFY_V3='

def remote_command(data):
    if hashlib.sha256(data).hexdigest()!=READER_SHA:
        raise ValueError('reader_hash_mismatch')
    root_bootstrap="import sys,hashlib; b=sys.stdin.buffer.read(1500001); assert hashlib.sha256(b).hexdigest()=="+repr(READER_SHA)+"; exec(compile(b,'<pinned-backup-reader-v3>','exec'),{'__name__':'__main__'})"
    remote_path='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27/scripts/backup_notify_v3/tu1nz_backup_notify_reader_v3.py'
    bootstrap="import pathlib,hashlib,subprocess; b=pathlib.Path("+repr(remote_path)+").read_bytes(); assert len(b)<=1500000 and hashlib.sha256(b).hexdigest()=="+repr(READER_SHA)+"; raise SystemExit(subprocess.run("+repr(['sudo','/usr/bin/python3','-I','-S','-c',root_bootstrap])+",input=b).returncode)"
    return '/usr/bin/python3 -I -c '+shlex.quote(bootstrap)

def argv(data):
    return ['ssh','-F','/dev/null','-tt','-p','2222','-o','HostKeyAlias=100.121.130.51',
        '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','BatchMode=yes',
        'chatops@100.121.130.51',remote_command(data)]

def main():
    if len(sys.argv)!=1 or sys.platform!='darwin':
        return 77
    for p in (BASE,READER):
        s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode & 0o077:
            raise ValueError('unsafe_local_path')
    data=READER.read_bytes();command=argv(data)
    os.umask(0o077)
    directory=BASE/('result-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    result=None;pending=b'';total=0
    # SSH retains terminal stdin so sudo reads a concealed password normally.
    # Only the fixed redacted JSON line is persisted; terminal output is not logged.
    with subprocess.Popen(command,stdout=subprocess.PIPE) as process:
        while True:
            chunk=os.read(process.stdout.fileno(),4096)
            if not chunk:break
            sys.stdout.buffer.write(chunk);sys.stdout.buffer.flush()
            total+=len(chunk)
            if total>8_000_000:
                process.terminate();raise ValueError('output_limit')
            pending+=chunk
            while b'\n' in pending:
                line,pending=pending.split(b'\n',1)
                text=line.decode('utf-8',errors='strict').strip()
                if PREFIX in text:
                    if result is not None:raise ValueError('duplicate_result')
                    result=json.loads(text.split(PREFIX,1)[1])
        rc=process.wait()
    if result is None:raise ValueError('missing_result')
    payload=(json.dumps({'ssh_returncode':rc,'reader_sha256':READER_SHA,'result':result},sort_keys=True,indent=2)+'\n').encode()
    temporary=directory/'result.tmp'
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())
    os.replace(temporary,directory/'result.json')
    print('Private redacted evidence:',str(directory/'result.json'))
    return rc

if __name__=='__main__':
    raise SystemExit(main())
