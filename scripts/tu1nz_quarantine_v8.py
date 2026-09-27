"""Exact-file fail-closed quarantine primitive; no CLI, sudo grant or live invocation.

The future pinned installer supplies a fixed target. Fixture mode only permits
current-user-owned temporary directories and must never be used by root.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

TARGET='/usr/local/bin/backup_notify.sh'
SOURCE_SHA='878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311'
GUARD=b'#!/usr/bin/python3 -I\n# TU1NZ quarantined untrusted root notification path.\nraise SystemExit(78)\n'
GUARD_SHA=hashlib.sha256(GUARD).hexdigest()
class Refused(RuntimeError):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def encode(o):return json.dumps(o,sort_keys=True,separators=(',',':')).encode()

class Quarantine:
 def __init__(self, backup, target=TARGET, fixture=False, fixture_sha=None):
  if fixture and os.geteuid()==0:raise Refused('root fixture forbidden')
  if not fixture and (os.geteuid()!=0 or target!=TARGET or fixture_sha is not None):raise Refused('fixed root contract')
  self.uid=os.geteuid();self.target=Path(target);self.backup=Path(backup)
  self.expected=fixture_sha if fixture else SOURCE_SHA
  self.fixture=fixture
  for p in (self.target.parent,self.backup):self._chain(p)
  if stat.S_IMODE(self.backup.stat().st_mode)!=0o700:raise Refused('backup mode')
  self.parent=os.open(self.target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  self.store=os.open(self.backup,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def _chain(self,p):
  paths=[p] if self.fixture else list(reversed(p.parents))+[p]
  for path in paths:
   s=path.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=self.uid or s.st_mode&0o022:raise Refused('unsafe ancestor')
   if hasattr(os,'listxattr') and any('posix_acl' in x for x in os.listxattr(path)):raise Refused('ancestor acl')
 def _read(self,dirfd,name,mode):
  fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=dirfd)
  try:
   s=os.fstat(fd)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=self.uid or stat.S_IMODE(s.st_mode)!=mode or s.st_nlink!=1:raise Refused('file identity')
   if not self.fixture and s.st_gid!=0:raise Refused('group drift')
   if hasattr(os,'listxattr') and os.listxattr(fd):raise Refused('unexpected xattr')
   data=b''
   while True:
    chunk=os.read(fd,65536)
    if not chunk:break
    data+=chunk
    if len(data)>2_000_000:raise Refused('size')
   after=os.fstat(fd)
   fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
   if fields(s)!=fields(after):raise Refused('read drift')
   return data,{'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink,'mtime_ns':s.st_mtime_ns,'atime_ns':s.st_atime_ns,'sha256':digest(data),'acl':'ABSENT','xattrs':'ABSENT'}
  finally:os.close(fd)
 def _atomic(self,dirfd,name,data,mode,replace=False):
  temp='.pending-'+secrets.token_hex(12)
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=dirfd)
  try:
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   if replace:os.replace(temp,name,src_dir_fd=dirfd,dst_dir_fd=dirfd)
   else:
    os.link(temp,name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
    os.unlink(temp,dir_fd=dirfd)
   os.fsync(dirfd)
  finally:
   try:os.unlink(temp,dir_fd=dirfd)
   except FileNotFoundError:pass
 def _checkpoint(self,state):
  data=encode({'state':state,'target':str(self.target),'original_sha256':self.expected,'guard_sha256':GUARD_SHA,'automatic_restore_original':False})
  # Existing checkpoint must be a private regular file, never an external link.
  try:self._read(self.store,'checkpoint.json',0o600)
  except FileNotFoundError:pass
  self._atomic(self.store,'checkpoint.json',data,0o600,replace=True)
 def _backup(self,source,meta):
  self._atomic(self.store,'original.bin',source,0o600)
  self._atomic(self.store,'metadata.json',encode(meta),0o600)
 def _proof(self):
  source,_=self._read(self.store,'original.bin',0o600);raw,_=self._read(self.store,'metadata.json',0o600);meta=json.loads(raw)
  if digest(source)!=self.expected or meta['sha256']!=self.expected or meta['mode']!=0o700:raise Refused('backup mismatch')
  return meta
 def _install_guard(self):
  data,meta=self._read(self.parent,self.target.name,0o700)
  if digest(data)==GUARD_SHA:return
  old=self._proof()
  if digest(data)!=self.expected or meta['device']!=old['device'] or meta['inode']!=old['inode']:raise Refused('target drift')
  self._atomic(self.parent,self.target.name,GUARD,0o700,replace=True)
 def verify(self):
  self._proof();data,_=self._read(self.parent,self.target.name,0o700)
  if digest(data)!=GUARD_SHA:raise Refused('guard mismatch')
  return True
 def apply(self,inject=lambda phase:None):
  # The same private transaction directory is the idempotency key.
  try:
   raw,_=self._read(self.store,'checkpoint.json',0o600);record=json.loads(raw)
  except FileNotFoundError:record=None
  if record is not None:
   if record.get('target')!=str(self.target) or record.get('original_sha256')!=self.expected:raise Refused('journal mismatch')
   self._proof();self.rollback();return
  source,meta=self._read(self.parent,self.target.name,0o700)
  if digest(source)!=self.expected:raise Refused('source drift')
  inject('BEFORE_BACKUP');self._backup(source,meta)
  try:
   inject('AFTER_BACKUP');self._checkpoint('INTENT');inject('AFTER_INTENT')
   self._install_guard();inject('AFTER_REPLACE');self.verify();inject('AFTER_VERIFY');self._checkpoint('QUARANTINED')
  except Exception:
   self.rollback();raise
 def rollback(self):
  # Security rollback intentionally cannot restore the untrusted executable.
  self._proof();self._install_guard();self.verify();self._checkpoint('QUARANTINED')
 def close(self):os.close(self.parent);os.close(self.store)
