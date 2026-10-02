"""Concrete guard production adapter; requires bound root file backend and journal.
No entrypoint. No action on import. No self-generated baseline or shell execution.
"""
import os,subprocess,hashlib
from production import PACKAGE,AUTHORITY,STATE,AUTH_SHA
from manifest import Refused
UNIT='tu1nz_delete_guard.service'
TIMER='tu1nz_delete_guard.timer'
DROPIN='/etc/systemd/system/'+UNIT+'.d/90-v11-authority.conf'
CHECKSUM='/usr/local/bin/checksum_verify'
TARGETS=(PACKAGE+'/guard.py',AUTHORITY,DROPIN,CHECKSUM)
DIRECTORIES={PACKAGE:(0,0,0o755),'/etc/tu1nz/docs-authority-v11':(0,0,0o700),STATE:(0,1001,0o750),STATE+'/results':(0,0,0o700),'/etc/systemd/system/'+UNIT+'.d':(0,0,0o755)}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/var/empty'}
ALLOWED=(('/usr/bin/systemctl','stop',TIMER),('/usr/bin/systemctl','start',TIMER),('/usr/bin/systemctl','start','--job-mode=fail',UNIT),('/usr/bin/systemctl','daemon-reload'),('/usr/bin/systemctl','show','--property=ActiveState,UnitFileState,Result,ExecMainStatus,InvocationID','--',UNIT),('/usr/bin/systemctl','show','--property=ActiveState,UnitFileState','--',TIMER))
def execute(argv):
 if os.geteuid()!=0 or tuple(argv) not in ALLOWED:raise Refused('ROOT_FIXED_COMMAND')
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,cwd='/',timeout=150)
 if r.returncode or len(r.stdout)>16384:raise Refused('SYSTEMD_FAILED')
 return r.stdout.decode()
def properties(raw):return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
class Adapter:
 def __init__(self,files,journal,run=execute):self.files=files;self.journal=journal;self.run=run
 def preflight(self,candidates,original_pins):
  if set(candidates)!=set(TARGETS) or set(original_pins)!=set(TARGETS):raise Refused('PATH_SET')
  for p,r in candidates.items():
   if set(r)!={'bytes','sha256','uid','gid','mode'} or r['uid']!=0 or r['gid']!=0 or r['mode'] not in (0o600,0o644,0o755) or hashlib.sha256(r['bytes']).hexdigest()!=r['sha256']:raise Refused('PAYLOAD')
  if candidates[AUTHORITY]['sha256']!=AUTH_SHA or candidates[AUTHORITY]['mode']!=0o600:raise Refused('AUTHORITY_PIN')
  before=self.files.snapshot(TARGETS,DIRECTORIES)
  if not self.files.matches(before,original_pins):raise Refused('ORIGINAL_DRIFT')
  service=properties(self.run(ALLOWED[4]));timer=properties(self.run(ALLOWED[5]))
  if service.get('ActiveState')!='inactive' or timer!={'ActiveState':'active','UnitFileState':'enabled'}:raise Refused('SCHEDULE_STATE')
  return {'files':before,'service':service,'timer':timer}
 def stage(self,checkpoint,candidates,proofs):
  if proofs!={'root_lock_held':True,'independent_watchdog_active_verified':True,'backup_bytes_and_acl_verified':True,'fresh_window_sufficient':True}:raise Refused('PREPARATION_PROOFS')
  if not self.files.same_snapshot(checkpoint['files']):raise Refused('FOREIGN_WRITER')
  self.journal.intent('GUARD_STAGE',checkpoint,sealed=False)
  self.files.create_declared_directories(DIRECTORIES)
  for p in (PACKAGE+'/guard.py',AUTHORITY):self.files.install_exact(p,candidates[p],checkpoint['files'])
  for p in (PACKAGE+'/guard.py',AUTHORITY):self.files.verify_exact(p,candidates[p])
  self.journal.verified('GUARD_STAGE')
 def cutover(self,checkpoint,candidates):
  if not self.files.originals_unchanged((DROPIN,CHECKSUM),checkpoint['files']):raise Refused('CONSUMER_DRIFT')
  if properties(self.run(ALLOWED[4])).get('ActiveState')!='inactive':raise Refused('RUNNING_GUARD')
  # Durable barrier BEFORE stopping timer or replacing consumers. Never reopen old trust.
  self.journal.intent('GUARD_CUTOVER',checkpoint,sealed=True)
  self.run(ALLOWED[0])
  if properties(self.run(ALLOWED[5])).get('ActiveState')!='inactive':raise Refused('TIMER_NOT_STOPPED')
  for p in (DROPIN,CHECKSUM):self.files.install_exact(p,candidates[p],checkpoint['files']);self.files.verify_exact(p,candidates[p])
  self.run(ALLOWED[3]);self.files.verify_loaded_consumer(UNIT,PACKAGE+'/guard.py')
  self.run(ALLOWED[2]);self.files.verify_fresh_status(AUTH_SHA)
  self.run(ALLOWED[1])
  if properties(self.run(ALLOWED[5]))!=checkpoint['timer']:raise Refused('TIMER_RESTORE')
  self.journal.verified('GUARD_CUTOVER')
 def recover(self,checkpoint,sealed):
  if sealed:
   self.run(ALLOWED[0])
   if properties(self.run(ALLOWED[5])).get('ActiveState')!='inactive':raise Refused('SECURED_STOP_FAILED')
   # Do not restart old service or restore mutable baseline authority.
   self.journal.terminal('SECURED_STOP');return 'SECURED_STOP'
  self.files.restore_owned_changes(checkpoint['files'])
  if not self.files.same_restored_snapshot(checkpoint['files']):raise Refused('ROLLBACK_FAILED')
  self.journal.terminal('ROLLED_BACK');return 'ROLLED_BACK'
