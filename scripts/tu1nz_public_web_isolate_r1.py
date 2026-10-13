"""Finite public-web privilege drop; no Docker/provider or Host mutation.

Invoked only by the three reviewed systemd !-ExecStart profiles. The manager
bootstrap establishes its mandatory minimal private user namespace. A missing namespace,
different account/mapping or privilege-drop failure denies BEFORE application
imports. UID/GID1001 remain stable for existing credentials/state/DB peer auth;
no supplementary NSS/admin groups or capabilities survive. This is not a
replacement for actual Host actor/daemon/alternative-delegation admission.
"""
import argparse
import ctypes
import grp
import json
import os
from pathlib import Path
import pwd
import sys
import select
import signal
import stat

APP='/opt/tu1nz_repos/adult-publishing-core'
STATE='/var/lib/tu1nz-adult-public-s9'
PROFILES={
 's7':('tu1nz-adult-public-s7.service',[
  APP+'/.venv/bin/tu1nz-public-s7','--contract','/etc/tu1nz/adult-commercial-s7-public.json']),
 's8-landing':('tu1nz-adult-public-s8-landing.service',[
  APP+'/.venv/bin/tu1nz-public-s8-landing','--contract','/etc/tu1nz/adult-commercial-s8-landing.json',
  '--aggregate-state',STATE+'/landing-aggregates.json']),
 'wms':('tu1nz-adult-public-s10-wms.service',[
  APP+'/.venv/bin/python','-m','tu1nz_exposure_s10.runtime',
  '--contract','/etc/tu1nz/adult-commercial-s10-wms.json','--copy','/etc/tu1nz/adult-commercial-s10-wms-copy.json',
  '--bot-contract','/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json',
  '--community-contract','/etc/tu1nz/adult-commercial-s10-2d-community.json',
  '--runtime-release-id','s10-2d-r3-5','--aggregate-state',STATE+'/landing-aggregates.json',
  '--traffic-quality-state',STATE+'/wms-traffic-quality.json'])}
class Denied(RuntimeError):
 def __init__(self,code,*,primary=None,abort=(),cleanup=()):
  super().__init__('PUBLIC_WEB_ISOLATION_'+code)
  self.primary=primary or 'PUBLIC_WEB_ISOLATION_'+code
  self.abort=list(abort);self.cleanup=list(cleanup)
def require(ok,code):
 if not ok:raise Denied(code)
def error_code(error):
 return error.primary if isinstance(error,Denied) else 'PUBLIC_WEB_ISOLATION_START_DENIED'
def non_dumpable():
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'NON_DUMPABLE_RED')
def interrupted(number,_frame):
 raise Denied('BOOTSTRAP_INTERRUPTED')
def mappings(path):
 rows=[tuple(map(int,line.split())) for line in Path(path).read_text().splitlines()]
 require(all(len(row)==3 for row in rows),'MAP_FORMAT_RED')
 return sorted(rows)
def prepare_credentials(unit):
 """S7-only private tmpfs view; retain the original read-only manager inputs.

 No persistent credential copy or metadata normalization. The inherited
 service mount namespace must already be private; overlay is only there.
 Existing S7 parser requires caller-owned0600 or its older root-managed
 profile. Keep that parser/data contract rather than weakening it for a
 systemd version-specific0400 layout. Application code is still unmodified.
 """
 require(os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt'),
         'PRIVATE_MOUNT_NAMESPACE_REQUIRED')
 directory=Path('/run/credentials')/unit
 require(os.environ.get('CREDENTIALS_DIRECTORY')==str(directory) and not directory.is_symlink(),
         'CREDENTIAL_DIRECTORY_RED')
 info=directory.stat()
 require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,1001) and
         not stat.S_IMODE(info.st_mode)&0o222 and os.statvfs(directory).f_flag&os.ST_RDONLY,
         'MANAGER_CREDENTIAL_DIRECTORY_PROFILE_RED')
 names={'s7_form_secret','s7_database_dsn'}
 require({p.name for p in directory.iterdir()}==names,'CREDENTIAL_INVENTORY_RED')
 values={}
 for name in names:
  fd=os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
     before.st_uid in (0,1001) and not stat.S_IMODE(before.st_mode)&0o222 and 1<=before.st_size<=4096,
     'MANAGER_CREDENTIAL_PROFILE_RED')
   raw=os.read(fd,4097);after=os.fstat(fd)
   require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
     (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
     'MANAGER_CREDENTIAL_READ_RED');values[name]=raw
  finally:os.close(fd)
 libc=ctypes.CDLL(None,use_errno=True)
 # Mount type/copy belong only to this already-private service namespace.
 flags=2|4|8  # NOSUID, NODEV, NOEXEC.
 require(libc.mount(b'tmpfs',os.fsencode(directory),b'tmpfs',flags,
                   b'mode=0500,uid=1001,gid=1001,size=32k')==0,'PRIVATE_CREDENTIAL_MOUNT_RED')
 for name,raw in values.items():
  fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:
   os.fchown(fd,1001,1001);os.fchmod(fd,0o600)
   written=0
   while written<len(raw):
    count=os.write(fd,raw[written:]);require(count>0,'PRIVATE_CREDENTIAL_WRITE_RED');written+=count
   os.fsync(fd)
  finally:os.close(fd)
 require(libc.mount(None,os.fsencode(directory),None,flags|1|32,None)==0,'PRIVATE_CREDENTIAL_SEAL_RED')
 require(os.statvfs(directory).f_flag&os.ST_RDONLY,'PRIVATE_CREDENTIAL_READONLY_RED')
 for name,raw in values.items():
  fd=os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   info=os.fstat(fd)
   require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==1001 and info.st_gid==1001
           and stat.S_IMODE(info.st_mode)==0o600 and os.read(fd,4097)==raw,'PRIVATE_CREDENTIAL_READBACK_RED')
  finally:os.close(fd)
def establish_namespace():
 """Clear groups BEFORE user-ns creation; maps belong only to our forked child.

 systemd PrivateUsers deliberately denies setgroups afterwards. The reviewed
 root bootstrap therefore creates/maps one owned namespace, joins it, reaps
 its empty creator, then drops identity/capabilities and execs the app.
 No arbitrary target PID, pathname, command, user or mapping is accepted.
 """
 require(sys.platform=='linux' and os.geteuid()==0,'PRIVATE_MANAGER_BOOTSTRAP_REQUIRED')
 require(not os.environ.get('LISTEN_FDS') and not os.environ.get('LISTEN_PID'),
         'UNEXPECTED_SOCKET_ACTIVATION_RED')
 require(pwd.getpwnam('chatops').pw_uid==1001 and grp.getgrnam('chatops').gr_gid==1001,'ACCOUNT_BINDING_RED')
 require(mappings('/proc/self/uid_map')==[(0,0,4294967295)] and
         mappings('/proc/self/gid_map')==[(0,0,4294967295)],'INITIAL_MANAGER_NAMESPACE_REQUIRED')
 os.setgroups([])
 ready_r=ready_w=done_r=done_w=ns=None;pid=None;reaped=False;primary=None;abort=[];cleanup=[]
 try:
  ready_r,ready_w=os.pipe2(os.O_CLOEXEC);done_r,done_w=os.pipe2(os.O_CLOEXEC)
  pid=os.fork()
 except BaseException:
  for fd in (ready_r,ready_w,done_r,done_w):
   if fd is not None:os.close(fd)
  raise
 if pid==0:
  try:
   os.close(ready_r);os.close(done_w)
   libc=ctypes.CDLL(None,use_errno=True)
   if libc.unshare(0x10000000)!=0:os._exit(125)  # CLONE_NEWUSER only.
   os.write(ready_w,b'R');os.close(ready_w)
   if not select.select([done_r],[],[],5)[0] or os.read(done_r,1)!=b'X':os._exit(125)
   os._exit(0)
  except BaseException:os._exit(125)
 try:
  os.close(ready_w);ready_w=None;os.close(done_r);done_r=None
  require(select.select([ready_r],[],[],5)[0] and os.read(ready_r,1)==b'R','NAMESPACE_CREATION_RED')
  root=Path('/proc')/str(pid)
  (root/'uid_map').write_text('0 0 1\n1001 1001 1\n')
  (root/'setgroups').write_text('deny\n')
  (root/'gid_map').write_text('0 0 1\n1001 1001 1\n')
  ns=os.open(root/'ns/user',os.O_RDONLY|os.O_CLOEXEC)
  libc=ctypes.CDLL(None,use_errno=True)
  require(libc.setns(ns,0x10000000)==0,'NAMESPACE_JOIN_RED')
  os.write(done_w,b'X');os.close(done_w);done_w=None
  _,code=os.waitpid(pid,0);reaped=True;require(os.waitstatus_to_exitcode(code)==0,'CREATOR_EXIT_RED')
 except BaseException as error:primary=error
 finally:
  # Do not allow a second interruption to abandon an owned creator. Never
  # signal an unrelated PID: our child is not reaped/reusable until waitpid.
  saved={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
  for sig in saved:signal.signal(sig,signal.SIG_IGN)
  if not reaped:
   try:
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
   except BaseException:abort.append('PUBLIC_WEB_ISOLATION_OWNED_CREATOR_ABORT_RED')
   try:os.waitpid(pid,0);reaped=True
   except BaseException:cleanup.append('PUBLIC_WEB_ISOLATION_OWNED_CREATOR_REAP_RED')
  for fd in (ready_r,ready_w,done_r,done_w,ns):
   if fd is not None:
    try:os.close(fd)
    except BaseException:cleanup.append('PUBLIC_WEB_ISOLATION_OWNED_DESCRIPTOR_CLOSE_RED')
  for sig,handler in saved.items():signal.signal(sig,handler)
 if primary is not None or abort or cleanup:
  raise Denied('NAMESPACE_DENIED',primary=error_code(primary) if primary is not None else
               'PUBLIC_WEB_ISOLATION_CREATOR_CLEANUP_RED',abort=abort,cleanup=cleanup) from None
 expected=[(0,0,1),(1001,1001,1)]
 require(mappings('/proc/self/uid_map')==expected and mappings('/proc/self/gid_map')==expected,
         'MINIMAL_PRIVATE_USER_NAMESPACE_REQUIRED')
 require(Path('/proc/self/setgroups').read_text().strip()=='deny' and not os.getgroups(),
         'GROUP_DROP_UNAVAILABLE')
def drop():
 libc=ctypes.CDLL(None,use_errno=True)
 non_dumpable()
 require(libc.prctl(38,1,0,0,0)==0,'NO_NEW_PRIVILEGES_RED')
 # Drop every bounding/ambient capability before losing namespace privilege.
 last=int(Path('/proc/sys/kernel/cap_last_cap').read_text());require(0<=last<=63,'CAPABILITY_PROFILE_RED')
 require(libc.prctl(47,4,0,0,0)==0,'AMBIENT_DROP_RED')
 for cap in range(last+1):require(libc.prctl(24,cap,0,0,0)==0,'BOUNDING_DROP_RED')
 require(not os.getgroups(),'SUPPLEMENTARY_GROUPS_REAPPEARED')
 os.setresgid(1001,1001,1001);os.setresuid(1001,1001,1001)
 non_dumpable()
 status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 require(os.getresuid()==(1001,1001,1001) and os.getresgid()==(1001,1001,1001) and not os.getgroups(),
         'EFFECTIVE_IDENTITY_RED')
 require(all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')) and
         status['NoNewPrivs'].strip()=='1','FINAL_CAPABILITIES_RED')
def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=tuple(PROFILES),required=True)
 args=p.parse_args();unit,command=PROFILES[args.profile];command=list(command)
 require(sys.platform=='linux' and os.geteuid()==0,'PRIVATE_MANAGER_BOOTSTRAP_REQUIRED')
 non_dumpable()
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
 credentials='/run/credentials/'+unit
 if args.profile=='s7':
  require(os.environ.get('CREDENTIALS_DIRECTORY')==credentials,'CREDENTIAL_DIRECTORY_RED')
  prepare_credentials(unit)
  command+=['--form-secret',credentials+'/s7_form_secret','--database-dsn',credentials+'/s7_database_dsn']
 establish_namespace()
 env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
 if args.profile=='wms':env['PYTHONPATH']=APP+'/src'
 drop()
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_DFL)
 os.execve(command[0],command,env)
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print(json.dumps({'event':'PUBLIC_WEB_ISOLATION_DENIED','primary':error_code(error),
    'abort':error.abort if isinstance(error,Denied) else [],
    'cleanup':error.cleanup if isinstance(error,Denied) else [],
    'application_exec':False}),file=sys.stderr)
  raise SystemExit(125)
