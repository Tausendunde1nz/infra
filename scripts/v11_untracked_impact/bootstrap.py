"""Reviewed inline bootstrap: only bound bytes are executed, from root staging."""
import hashlib
import json
import time
import os
from pathlib import Path
import stat
import sys
import tempfile

class Refused(RuntimeError):pass

def trusted_dir(path,owner):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 s=os.fstat(fd)
 if s.st_uid!=owner or s.st_mode&0o022 or any('posix_acl' in x for x in os.listxattr(fd)):
  os.close(fd);raise Refused('UNTRUSTED_DIRECTORY')
 return fd

def copy_verified(source,directory,expected,source_uid):
 """Hash is authority; path and inode alone are never an execution guarantee."""
 if len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):raise Refused('HASH_FORMAT')
 d=trusted_dir(directory,os.geteuid())
 try:
  parts=Path(source).parts
  parentfd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
  try:
   for part in parts[1:-1]:
    nextfd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd);os.close(parentfd);parentfd=nextfd
   fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parentfd)
  finally:os.close(parentfd)
  if not stat.S_ISREG(os.fstat(fd).st_mode):
   os.close(fd);raise Refused('SOURCE_TYPE')
  with os.fdopen(fd,'rb') as f:
   a=os.fstat(f.fileno())
   if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_uid!=source_uid or a.st_size>2_000_000:raise Refused('SOURCE_IDENTITY')
   b=f.read(2_000_001);z=os.fstat(f.fileno())
  if len(b)>2_000_000 or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('SOURCE_RACE')
  f=os.open('collector.py',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  with os.fdopen(f,'w+b') as target:
   os.fchmod(target.fileno(),0o600);target.write(b);target.flush();os.fsync(target.fileno());target.seek(0)
   copied=target.read(2_000_001);s=os.fstat(target.fileno())
   if s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise Refused('COPY_IDENTITY')
   if any('posix_acl' in x for x in os.listxattr(target.fileno())):raise Refused('COPY_ACL')
   if hashlib.sha256(copied).hexdigest()!=expected:raise Refused('COPY_HASH')
  os.fsync(d)
  return str(Path(directory)/'collector.py')
 finally:os.close(d)

def record(root,name,value):
 d=trusted_dir(root,os.geteuid());tmp='.'+name+'-'+os.urandom(8).hex()
 raw=json.dumps(value,sort_keys=True).encode()+b'\n'
 try:
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
  os.link(tmp,name,src_dir_fd=d,dst_dir_fd=d,follow_symlinks=False);os.unlink(tmp,dir_fd=d);os.fsync(d)
 finally:
  try:os.unlink(tmp,dir_fd=d)
  except FileNotFoundError:pass
  os.close(d)

def prepare_copy(source,root,expected,source_uid):
 record(root,'bootstrap-start.json',{'status':'PREPARING_READONLY_COPY','expected_sha256':expected,'start_ns':time.monotonic_ns()})
 try:
  target=copy_verified(source,root/'staging',expected,source_uid)
  record(root,'bootstrap-complete.json',{'status':'COPY_VERIFIED_BEFORE_EXECUTION','sha256':expected,'end_ns':time.monotonic_ns()})
  return target
 except BaseException as e:
  record(root,'bootstrap-aborted.json',{'status':'ABORTED_BEFORE_EXECUTION','error_class':type(e).__name__,'end_ns':time.monotonic_ns()})
  raise

def main():
 if os.geteuid()!=0 or len(sys.argv)!=3:raise Refused('ROOT_ARGUMENTS')
 source,expected=sys.argv[1:]
 allowed='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27/scripts/v11_untracked_impact/collector.py'
 if source!=allowed:raise Refused('SOURCE_PATH')
 for p in ('/','/var','/var/lib'):
  fd=trusted_dir(p,0);os.close(fd)
 os.umask(0o077)
 root=Path(tempfile.mkdtemp(prefix='tu1nz-v11-untracked-evidence-',dir='/var/lib'))
 os.chown(root,0,1001);root.chmod(0o710);os.mkdir(root/'staging',0o700)
 print('V11_UNTRACKED_EVIDENCE_ROOT='+str(root),flush=True)
 target=prepare_copy(source,root,expected,1001)
 for p in (root/'staging',root,root.parent):
  fd=trusted_dir(p,0);os.fsync(fd);os.close(fd)
 # Restrictive file is already immutable to chatops; execution never reopens
 # the chatops source. No user import path, shell, env or working directory.
 os.chdir('/')
 os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B',target],
   {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})

if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('CHECKOUT_BOOTSTRAP_REFUSED:'+type(e).__name__,file=sys.stderr);raise SystemExit(3)
