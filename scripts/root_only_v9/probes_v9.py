"""Bounded kernel checks used by the later root transaction. Never run on import."""
import ctypes
import errno
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys
import socket
import signal
import time
from policy_v9 import Refused,SOCKET,CHATOPS_UID,DOCKER_GID
from audit_v9 import proc_identity

PROBE_CODE='''import socket,errno,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2)
try:
 s.connect('/run/docker.sock')
except OSError as e:
 if e.errno==errno.EACCES:sys.exit(0)
 if e.errno==errno.ENOENT:sys.exit(10)
 sys.exit(12)
else:sys.exit(11)
finally:s.close()
'''


def access_bits(st,acl,uid,gids):
 if uid==st.st_uid:return (st.st_mode>>6)&7
 if not acl:return (st.st_mode>>3)&7 if st.st_gid in gids else st.st_mode&7
 if len(acl)<4 or struct.unpack('<I',acl[:4])[0]!=2 or (len(acl)-4)%8:raise Refused('ACL format')
 entries=[struct.unpack('<HHI',acl[i:i+8]) for i in range(4,len(acl),8)]
 mask=next((p for tag,p,who in entries if tag==16),7)
 named=[p for tag,p,who in entries if tag==2 and who==uid]
 if named:return named[0]&mask
 matches=[p for tag,p,who in entries if (tag==4 and st.st_gid in gids) or (tag==8 and who in gids)]
 if matches:
  result=0
  for bits in matches:result|=bits
  return result&mask
 return next((p for tag,p,who in entries if tag==32),st.st_mode&7)


def acl(path):
 try:return os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:
  if e.errno in (errno.ENODATA,errno.ENOTSUP):return b''
  raise


def extra_gid_interfaces(root=Path('/'),deadline_seconds=180,max_entries=2_000_000):
 if os.geteuid()!=0:raise Refused('root visibility required')
 user=pwd.getpwnam('chatops');gids=set(os.getgrouplist('chatops',user.pw_gid))|{DOCKER_GID}
 without=gids-{DOCKER_GID};start=time.monotonic();todo=[root];seen=set();count=0;hits=[]
 # /proc task authority is checked separately. sysfs and device nodes are
 # retained here: a group-writable control node must not be overlooked.
 excluded={'/proc'}
 while todo:
  p=todo.pop()
  if str(p) in excluded:continue
  if time.monotonic()-start>deadline_seconds or count>=max_entries:raise Refused('GID scan incomplete')
  try:s=p.lstat()
  except FileNotFoundError:continue
  count+=1
  if stat.S_ISLNK(s.st_mode):continue  # Aliases inherit the target's permission boundary.
  try:a=acl(p)
  except FileNotFoundError:continue
  with_bits=access_bits(s,a,user.pw_uid,gids);without_bits=access_bits(s,a,user.pw_uid,without)
  if str(p)!=SOCKET and with_bits&2 and not without_bits&2:
   hits.append({'path':str(p),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'type':stat.S_IFMT(s.st_mode),'dev':s.st_dev,'ino':s.st_ino})
  if stat.S_ISDIR(s.st_mode) and with_bits&1:
   key=(s.st_dev,s.st_ino)
   if key in seen:continue
   seen.add(key)
   try:todo.extend(p.iterdir())
   except FileNotFoundError:continue
 return {'examined':count,'extra_interfaces':hits,'scope':'reachable persistent pathname DAC/ACL; endpoint and open-FD audits required separately'}


def negative_context_probe(identity):
 if os.geteuid()!=0:raise Refused('root probe required')
 pid=identity['pid'];proc=Path('/proc')/str(pid)
 if proc_identity(proc)!=identity:raise Refused('probe PID identity drift')
 if len(set(identity['uid']))!=1 or identity['uid'][0]!=CHATOPS_UID or len(set(identity['gid']))!=1:raise Refused('nonuniform credentials')
 if identity['cap_eff'] or identity['cap_prm']:raise Refused('capability-bearing context')
 if dict(identity['namespace'])['user']!=os.readlink('/proc/self/ns/user'):raise Refused('user namespace needs separate contract')
 fds={n:os.open(proc/'ns'/n,os.O_RDONLY|os.O_CLOEXEC) for n in ('mnt','net')}
 fds['root']=os.open(proc/'root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  if proc_identity(proc)!=identity:raise Refused('probe PID reuse')
  libc=ctypes.CDLL(None,use_errno=True)
  child=os.fork()
  if child==0:
   try:
    for n in ('mnt','net'):
     if libc.setns(fds[n],0)!=0:os._exit(70)
    root=os.fstat(fds['root'])
    if (root.st_dev,root.st_ino)!=(identity['root_dev'],identity['root_ino']):os._exit(73)
    os.fchdir(fds['root']);os.chroot('.');os.chdir('/')
    for fd in fds.values():os.close(fd)
    os.setgroups(list(identity['groups']));os.setgid(identity['gid'][0]);os.setuid(CHATOPS_UID)
    if libc.prctl(38,1,0,0,0)!=0:os._exit(71)
    denied=False
    for target in ('/run/docker.sock','/var/run/docker.sock'):
     sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(2)
     try:sock.connect(target)
     except OSError as error:
      if error.errno==errno.EACCES:denied=True
      elif error.errno!=errno.ENOENT:os._exit(12)
     else:os._exit(11)
     finally:sock.close()
    os._exit(0 if denied else 10)
   except BaseException:os._exit(72)
  # Child never execs an interpreter from the potentially different mount view.
  deadline=time.monotonic()+5
  while True:
   pid,status=os.waitpid(child,os.WNOHANG)
   if pid:break
   if time.monotonic()>=deadline:
    os.kill(child,signal.SIGKILL);os.waitpid(child,0);raise Refused('context probe timeout')
   time.sleep(0.01)
  code=os.waitstatus_to_exitcode(status)
  if code not in (0,10):raise Refused('context obtained access or probe failed')
  if proc_identity(proc)!=identity:raise Refused('context changed during probe')
  return 'EACCES' if code==0 else 'SOCKET_ABSENT_IN_NAMESPACE'
 finally:
  for fd in fds.values():os.close(fd)


def fresh_probe():
 if os.geteuid()!=0:raise Refused('root probe required')
 u=pwd.getpwnam('chatops');groups=os.getgrouplist('chatops',u.pw_gid)
 def demote():os.setgroups(groups);os.setgid(u.pw_gid);os.setuid(u.pw_uid)
 r=subprocess.run(['/usr/bin/python3','-I','-S','-c',PROBE_CODE],stdin=subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,preexec_fn=demote,
  env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/')
 if r.returncode!=0 or r.stdout or r.stderr:raise Refused('fresh chatops socket access not denied by DAC')
 return True
