"""Durable transaction kernel. No host mutation adapter or activation entrypoint.

Callers must be pinned root-owned code; snapshots may contain secrets and remain
private. A watchdog uses the same journal after acquiring the same exclusive lock.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time

STEPS = ('preflight', 'trendwatch', 'root-doc', 'root-compose', 'chatops-gid',
         'broker-sudo', 'final-validation')
SECURITY_TRIGGERS = frozenset(('trendwatch','root-doc','root-compose'))

class Closed(RuntimeError):
    pass

def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

class Journal:
    def __init__(self, directory):
        self.path=Path(directory)
        if os.geteuid()==0:
            for parent in reversed(self.path.parents):
                ps=parent.lstat()
                if not stat.S_ISDIR(ps.st_mode) or ps.st_uid!=0 or ps.st_mode & 0o022:
                    raise Closed('unsafe root journal ancestor')
                if any('posix_acl' in x for x in os.listxattr(parent)):
                    raise Closed('unsafe root ancestor ACL')
        s=self.path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:
            raise Closed('unsafe journal directory')
        if any('posix_acl' in x for x in os.listxattr(self.path)):
            raise Closed('unexpected ACL')
        self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            self.lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            self._check(os.fstat(self.lock))
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:
            if hasattr(self,'lock'):os.close(self.lock)
            os.close(self.fd)
            raise

    def _check(self,s):
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:
            raise Closed('unsafe journal file')

    def read(self):
        try:fd=os.open('checkpoint.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
        except FileNotFoundError:return {'version':7,'status':'NEW','steps':[]}
        with os.fdopen(fd,'rb') as f:
            self._check(os.fstat(f.fileno()));data=f.read(16_000_001)
        if len(data)>16_000_000:raise Closed('checkpoint size')
        envelope=json.loads(data)
        if hashlib.sha256(encode(envelope['payload'])).hexdigest()!=envelope['sha256']:
            raise Closed('checkpoint checksum')
        return envelope['payload']

    def write(self,value):
        payload=encode({'payload':value,'sha256':hashlib.sha256(encode(value)).hexdigest()})
        if len(payload)>16_000_000:raise Closed('checkpoint size')
        name='.pending-'+secrets.token_hex(16)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            with os.fdopen(fd,'wb') as f:
                self._check(os.fstat(f.fileno()));f.write(payload);f.flush();os.fsync(f.fileno())
            # Validate the existing checkpoint before replacement, including symlinks.
            try:
                s=os.stat('checkpoint.json',dir_fd=self.fd,follow_symlinks=False);self._check(s)
            except FileNotFoundError:pass
            os.replace(name,'checkpoint.json',src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:os.unlink(name,dir_fd=self.fd)
            except FileNotFoundError:pass

    def step(self,name,adapter,expected):
        record=self.read()
        if record['status'] not in ('NEW','CHECKPOINT') or len(record['steps'])>=len(STEPS) or name!=STEPS[len(record['steps'])]:
            raise Closed('phase order or unresolved intent')
        before=adapter.snapshot(name)
        if before!=expected:raise Closed('drift')
        entry={'name':name,'before':before,'status':'INTENT','monotonic_ns':time.monotonic_ns()}
        record['steps'].append(entry);record['status']='INTENT';self.write(record)
        try:
            adapter.apply(name)
            after=adapter.snapshot(name)
            if adapter.validate(name,before,after) is not True:raise Closed('postcondition')
            entry.update(status='DONE',after=after);record['status']='CHECKPOINT';self.write(record)
        except Exception:
            self.rollback_current(adapter)
            raise

    def rollback_current(self,adapter):
        record=self.read()
        if not record['steps']:raise Closed('no rollback snapshot')
        entry=record['steps'][-1]
        if entry['status'] not in ('INTENT','DONE','ROLLBACK_FAILED'):raise Closed('invalid rollback state')
        quarantine=entry['name'] in SECURITY_TRIGGERS
        try:
            adapter.restore(entry['name'],entry['before'],quarantine=quarantine)
            if adapter.verify_restore(entry['name'],entry['before'],quarantine=quarantine) is not True:
                raise Closed('rollback postcondition')
        except Exception:
            entry['status']='ROLLBACK_FAILED';record['status']='ROLLBACK_FAILED';self.write(record);raise
        entry['status']='QUARANTINED' if quarantine else 'ROLLED_BACK'
        record['status']='STOPPED';self.write(record)

    def finish(self,adapter):
        record=self.read()
        if record['status']!='CHECKPOINT' or [r['name'] for r in record['steps']]!=list(STEPS):
            raise Closed('incomplete')
        if adapter.final_validation() is not True:raise Closed('final validation')
        record['status']='COMPLETE';self.write(record)

    def close(self):
        os.close(self.lock);os.close(self.fd)
