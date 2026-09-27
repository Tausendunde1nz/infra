#!/usr/bin/python3 -I
"""Installed-only worker/watchdog entrypoint. Not a repository activation CLI."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

PACKAGE=Path('/usr/local/libexec/tu1nz-root-only-v9')
ROOT=Path('/var/lib/tu1nz-root-only-v9')


def load():
 if os.geteuid()!=0 or Path(__file__)!=PACKAGE/'entry_v9.py':raise RuntimeError('installed root entry only')
 # Bootstrap the loader using the same protected ancestor/descriptor boundary.
 for p in list(reversed(PACKAGE.parents))+[PACKAGE]:
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('package ancestry')
  if any('posix_acl' in x for x in os.listxattr(p)):raise RuntimeError('package ACL')
 def read(name):
  p=PACKAGE/name;s=p.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_nlink!=1:raise RuntimeError('package file')
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   b=os.fstat(f.fileno());data=f.read(8_000_001);a=os.fstat(f.fileno())
  if len(data)>8_000_000 or (s.st_dev,s.st_ino)!=(b.st_dev,b.st_ino) or (b.st_size,b.st_mtime_ns,b.st_ctime_ns)!=(a.st_size,a.st_mtime_ns,a.st_ctime_ns):raise RuntimeError('package race')
  return data
 manifest=json.loads(read('manifest.json'));raw=read('loader_v9.py')
 if hashlib.sha256(raw).hexdigest()!=manifest['modules']['loader_v9']:raise RuntimeError('loader checksum')
 ns={'__name__':'pinned_bootstrap','__file__':str(PACKAGE/'loader_v9.py')};exec(compile(raw,ns['__file__'],'exec'),ns)
 ns['install'](manifest['modules'])
 return manifest


def execute(mode,manifest):
 from transaction_v9 import Store,Transaction,watchdog_due
 from host_v9 import Host
 from command_v9 import checked
 from loader_v9 import protected_read
 from policy_v9 import PHASES,Refused
 import time
 import signal
 def interrupted(sig,frame):raise InterruptedError('worker interrupted')
 if mode=='worker':
  signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 elif mode=='watchdog':
  # Read-only inspection must work while the worker holds the exclusive lock.
  envelope=json.loads(protected_read(ROOT/'state.json'))
  from transaction_v9 import encoded
  state=envelope['data']
  if hashlib.sha256(encoded(state)).hexdigest()!=envelope['sha256']:raise Refused('watchdog checkpoint digest')
  boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if state['status'] in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):
   if state.get('watchdog_disabled') is True:return 0
   cleanup_store=Store(ROOT)
   try:
    Host(cleanup_store,manifest).disable_watchdog();state['watchdog_disabled']=True;cleanup_store.write(state)
   finally:cleanup_store.close()
   return 0
  if not watchdog_due(state,boot,time.monotonic_ns()):return 0
  # Stop only our worker cgroup. It catches TERM and attempts rollback; the
  # independently installed watchdog subsequently verifies/retries it.
  checked(['/usr/bin/systemctl','stop','tu1nz-root-only-v9.service'],timeout=620)
 else:raise Refused('entry mode')
 store=Store(ROOT)
 try:
  host=Host(store,manifest);tx=Transaction(store,host)
  if mode=='watchdog':
   if store.read()['status'] not in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):tx.rollback()
   host.disable_watchdog();state=store.read();state['watchdog_disabled']=True;store.write(state);return 0
  try:
   state=store.read()
   if state['status']!='PREPARED' or state['steps']:raise Refused('worker is not a fresh transaction')
   for phase in PHASES:tx.step(phase)
   tx.finish();return 0
  except BaseException:
   state=store.read()
   if state and state['status'] not in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):
    tx.rollback()
   # The independent watchdog cleans its own timer after terminal rollback.
   raise
 finally:store.close()


def main():
 try:
  if len(sys.argv)!=2 or sys.argv[1] not in ('worker','watchdog'):raise RuntimeError('entry arguments')
  manifest=load();return execute(sys.argv[1],manifest)
 except BaseException as e:
  # Never print exception text, argv, environment, root source or tracebacks.
  print(json.dumps({'status':'STOPPED','error_class':type(e).__name__}),flush=True)
  return 70

if __name__=='__main__':raise SystemExit(main())
