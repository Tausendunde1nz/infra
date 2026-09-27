"""Read-only kernel projection for integrated root preflight; no standalone reader."""
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from policy_v9 import Refused,SOCKET
from command_v9 import checked

class TopologyChanged(Refused):pass


def socket_identity(path=SOCKET):
 s=Path(path).lstat()
 if not stat.S_ISSOCK(s.st_mode) or s.st_nlink!=1:raise Refused('socket type/link')
 if os.listxattr(path):raise Refused('unreviewed socket xattrs/ACL')
 return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}


def peer_ids(text):
 peers=set();servers=set();listeners=set()
 for line in text.splitlines():
  if '/run/docker.sock' not in line:continue
  m=re.search(r'(?:^|\s)/run/docker\.sock\s+(\d+)\s+\*\s+(\d+)(?:\s|$)',line)
  if not m:raise Refused('unparsed docker socket record')
  local,peer=map(int,m.groups())
  if 'ESTAB' in line:
   if not peer:raise Refused('missing peer')
   peers.add(peer);servers.add(local)
  elif 'LISTEN' in line:listeners.add(local)
  else:raise Refused('unexpected socket state')
 if len(listeners)!=1:raise Refused('listener count')
 return peers,servers,listeners


def proc_identity(proc):
 raw=(proc/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
 status={l.split(':',1)[0]:l.split(':',1)[1].strip() for l in (proc/'status').read_text().splitlines() if ':' in l}
 uid=tuple(map(int,status['Uid'].split()));gid=tuple(map(int,status['Gid'].split()))
 namespaces=tuple((n,os.readlink(proc/'ns'/n)) for n in ('mnt','net','user'))
 root=(proc/'root').stat()
 return {'pid':int(proc.name),'tgid':int(status.get('Tgid',proc.name)),'root_dev':root.st_dev,'root_ino':root.st_ino,'start_ticks':int(tail[19]),'uid':uid,'gid':gid,
  'groups':tuple(map(int,status['Groups'].split())),'cgroup':(proc/'cgroup').read_text().strip(),
  'namespace':namespaces,'cap_eff':int(status['CapEff'],16),'cap_prm':int(status['CapPrm'],16)}


def fd_owners(inodes,proc_root=Path('/proc'),socket_file=None,path_handles=None):
 owners={n:[] for n in inodes};unreadable=[];count=0;deadline=time.monotonic_ns()+20_000_000_000
 def tasks():
  for leader in proc_root.iterdir():
   if not leader.name.isdigit():continue
   try:
    for task in (leader/'task').iterdir():
     if task.name.isdigit():yield task
   except FileNotFoundError:continue
 for proc in tasks():
  try:
   before=proc_identity(proc);matches=[];path_matches=[]
   for fd in (proc/'fd').iterdir():
    count+=1
    if count>1_000_000 or time.monotonic_ns()>deadline:raise Refused('FD audit budget exhausted')
    try:link=os.readlink(fd)
    except FileNotFoundError:continue
    m=re.fullmatch(r'socket:\[(\d+)\]',link)
    if m and int(m.group(1)) in inodes:matches.append((int(m.group(1)),int(fd.name)))
    elif socket_file is not None and link.startswith('/'):
     try:meta=fd.stat()
     except FileNotFoundError:continue
     if stat.S_ISSOCK(meta.st_mode) and (meta.st_dev,meta.st_ino)==(socket_file['dev'],socket_file['ino']):path_matches.append(int(fd.name))
   after=proc_identity(proc)
   if before!=after:
    if matches or path_matches:raise Refused('pid credentials changed during FD audit')
    continue
   for ino,fd in matches:owners[ino].append({'identity':before,'fd':fd})
   if path_handles is not None:
    for fd in path_matches:path_handles.append({'identity':before,'fd':fd,'kind':'PATH_HANDLE_NOT_CONNECTED'})
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:unreadable.append(int(proc.name))
 if unreadable:raise Refused('incomplete privileged FD visibility')
 if any(not rows for rows in owners.values()):raise TopologyChanged('unattributed connected peer')
 return owners


def audit(ss='/usr/bin/ss'):
 if os.geteuid()!=0:raise Refused('root metadata visibility required')
 before=socket_identity();start=time.monotonic_ns()
 first=checked([ss,'-xaneH'],timeout=10,limit=4_000_000)
 peers,servers,listeners=peer_ids(first.decode('utf8','strict'))
 path_handles=[]
 owners=fd_owners(peers|servers|listeners,socket_file=before,path_handles=path_handles)
 # Repeat socket diagnostic after FD scan to detect newly accepted connections.
 second=checked([ss,'-xaneH'],timeout=10,limit=4_000_000)
 p2,s2,l2=peer_ids(second.decode('utf8','strict'))
 after=socket_identity()
 if before!=after or listeners!=l2:raise Refused('socket identity changed')
 if peers!=p2 or servers!=s2:raise TopologyChanged('connected topology changed')
 return {'socket':before,'peers':owners,'path_handles':path_handles,'client_inodes':sorted(peers),'server_inodes':sorted(servers),'listener_inodes':sorted(listeners),'monotonic_start_ns':start,'monotonic_end_ns':time.monotonic_ns()}


def fixed_cutover(expected,on_intent=None):
 """Authority-monotone two-syscall transaction, NOT a false atomic-chown claim."""
 if os.geteuid()!=0:raise Refused('root required')
 if socket_identity()!=expected:raise Refused('socket drift')
 fd=os.open(SOCKET,os.O_PATH|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(expected['dev'],expected['ino'],expected['uid'],expected['gid'],expected['mode']):raise Refused('inode/metadata reuse')
  if on_intent is not None:on_intent()
  anchored='/proc/self/fd/'+str(fd)
  # First revoke group write. Changing ownership afterward never reopens access.
  os.chmod(anchored,0o600)
  os.chown(anchored,0,0)
  after=socket_identity()
  if after!={**expected,'uid':0,'gid':0,'mode':0o600}:raise Refused('cutover verification')
  return after
 finally:os.close(fd)


def restore_socket(expected_current,original,sealed):
 if sealed:raise Refused('security seal forbids reopening Docker authority')
 if os.geteuid()!=0 or socket_identity()!=expected_current:raise Refused('rollback socket drift')
 if (original['dev'],original['ino'])!=(expected_current['dev'],expected_current['ino']):raise Refused('different socket incarnation')
 fd=os.open(SOCKET,os.O_PATH|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if (s.st_dev,s.st_ino)!=(original['dev'],original['ino']):raise Refused('rollback race')
  anchored='/proc/self/fd/'+str(fd)
  os.chown(anchored,original['uid'],original['gid']);os.chmod(anchored,original['mode'])
  if socket_identity()!=original:raise Refused('rollback verification')
 finally:os.close(fd)


def rollback_postimage(original,current,write_started):
 if not write_started:
  if current!=original:raise Refused('socket changed before our write intent')
  return current
 allowed=(original,{**original,'mode':0o600},{**original,'mode':0o600,'uid':0,'gid':0})
 if current not in allowed:raise Refused('foreign socket postimage')
 return current
