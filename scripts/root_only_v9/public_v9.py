"""Root-written nonsecret progress projection; never a source of authorization."""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from policy_v9 import Refused,PHASES
PATH=Path('/run/tu1nz-root-only-v9.status.json')

def projection(state):
 status=state['status']
 if status not in ('PREPARED','CHECKPOINT','INTENT','ROLLBACK_INTENT','ROLLBACK_FAILED','COMPLETE','ROLLED_BACK','SECURED_STOP'):raise Refused('public status')
 if status=='COMPLETE' and state.get('watchdog_disabled') is not True:status='FINALIZATION_PENDING'
 phase=state['steps'][-1]['phase'] if state['steps'] else 'backup'
 if phase not in PHASES:raise Refused('public phase')
 capsule=state['capsule_sha256']
 if not re.fullmatch('[a-f0-9]{64}',capsule):raise Refused('public capsule binding')
 return {'version':9,'status':status,'phase':phase,'awaiting_client':state.get('awaiting_client') is True,
  'capsule_sha256':capsule,'deadline_ns':state['deadline_ns'],'monotonic_ns':time.monotonic_ns(),'boot_id':state['boot_id']}


def publish(state):
 if os.geteuid()!=0:raise Refused('root publisher required')
 s=PATH.parent.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused('public directory')
 try:
  s=PATH.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o644 or s.st_nlink!=1:raise Refused('public file')
  old=json.loads(PATH.read_text())
  if old['capsule_sha256']!=state['capsule_sha256']:raise Refused('public foreign transaction')
 except FileNotFoundError:pass
 raw=json.dumps(projection(state),sort_keys=True).encode();tmp=PATH.parent/('.tu1nz-status-'+secrets.token_hex(12))
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 try:
  with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o644);f.write(raw);f.flush();os.fsync(f.fileno())
  os.replace(tmp,PATH);d=os.open(PATH.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:
  try:tmp.unlink()
  except FileNotFoundError:pass
