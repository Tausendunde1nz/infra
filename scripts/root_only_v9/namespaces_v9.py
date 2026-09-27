"""Metadata-only namespace coverage without executing anything in a foreign root."""
import errno
import os
from pathlib import Path
import pwd
import stat
import time
from audit_v9 import proc_identity,socket_identity
from probes_v9 import access_bits
from policy_v9 import Refused,DOCKER_GID


def scan_view(pid,identity,seconds=180,max_entries=2_000_000):
 if os.geteuid()!=0:raise Refused('root visibility required')
 proc=Path('/proc')/str(pid)
 if proc_identity(proc)!=identity:raise Refused('view identity changed')
 u=pwd.getpwnam('chatops');with_gid=set(identity['groups'])|{identity['gid'][0],DOCKER_GID};without=with_gid-{DOCKER_GID}
 root=os.open(proc/'root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 start=time.monotonic_ns();count=0;hits=[];seen=set();docker=socket_identity()
 def visit(fd,relative):
  nonlocal count
  s=os.fstat(fd);key=(s.st_dev,s.st_ino)
  if key in seen:return
  seen.add(key)
  # scandir operates on an already pinned descriptor; no namespace interpreter,
  # program, shell, NSS or import is loaded from the observed container root.
  with os.scandir(fd) as iterator:
   for entry in iterator:
    count+=1
    if count>max_entries or time.monotonic_ns()-start>seconds*1_000_000_000:raise Refused('namespace scan incomplete')
    rel=relative+'/'+entry.name
    if rel=='/proc':continue
    try:s=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError:continue
    if stat.S_ISLNK(s.st_mode):continue
    path='/proc/self/fd/'+str(fd)+'/'+entry.name
    try:a=os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
    except OSError as e:
     if e.errno in (errno.ENODATA,errno.ENOTSUP):a=b''
     elif e.errno==errno.ENOENT:continue
     else:raise
    now=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
    attrs=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid)
    if attrs(s)!=attrs(now):raise Refused('namespace entry changed')
    yes=access_bits(s,a,1001,with_gid);no=access_bits(s,a,1001,without)
    is_docker=(s.st_dev,s.st_ino)==(docker['dev'],docker['ino'])
    if not is_docker and yes&2 and not no&2:
     hits.append({'path':rel,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'type':stat.S_IFMT(s.st_mode),'dev':s.st_dev,'ino':s.st_ino})
    if stat.S_ISDIR(s.st_mode) and yes&1:
     child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
     try:
      if attrs(os.fstat(child))!=attrs(s):raise Refused('namespace directory swap')
      visit(child,rel)
     finally:os.close(child)
 try:visit(root,'')
 finally:os.close(root)
 if proc_identity(proc)!=identity:raise Refused('namespace subject changed')
 return {'identity':identity,'examined':count,'extra_interfaces':hits}


def view_key(ident):
 p=Path('/proc')/str(ident['pid']);s=(p/'root').stat()
 return (dict(ident['namespace'])['mnt'],dict(ident['namespace'])['user'],s.st_dev,s.st_ino,tuple(ident['gid']),tuple(ident['groups']))


def audit_views(contexts):
 results={}
 for ident in contexts:
  key=view_key(ident)
  if key not in results:results[key]=scan_view(ident['pid'],ident)
 for result in results.values():
  if result['extra_interfaces']:raise Refused('additional namespace GID interface')
 return {'verified':True,'views':list(results.values())}
