"""One bounded root validation, fixed test names, external cleanup controller.
Importing this module does nothing. No production-profile execution is possible.
"""
import os,sys,time,signal,stat,json,hashlib
from pathlib import Path
import anchor,manager,phase0,phase1,install,host,decommission
from publication import Journal
CREATION_HOOK=lambda path,identity:None
class ValidationTimeout(RuntimeError):pass

def exclusive_file(path,data,mode):
 p=Path(path);parent=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  f=os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
  try:
   os.fchmod(f,mode)
   st=os.fstat(f);CREATION_HOOK(p,(st.st_dev,st.st_ino))
   with os.fdopen(f,'wb',closefd=False) as out:out.write(data);out.flush();os.fsync(f)
   s=os.fstat(f)
   if s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or os.listxattr(f):raise anchor.Refused('ROOT_TEST_FILE_METADATA')
  finally:os.close(f)
  os.fsync(parent)
 finally:os.close(parent)
 return (s.st_dev,s.st_ino,anchor.digest(data))
def remove_exact(path,identity):
 p=Path(path);s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or (s.st_dev,s.st_ino)!=(identity[0],identity[1]) or anchor.digest(p.read_bytes())!=identity[2]:raise anchor.Refused('TEST_CLEANUP_FILE_DRIFT')
 p.unlink();fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def wait_for(predicate,seconds):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  if predicate():return
  time.sleep(.1)
 raise ValidationTimeout('OBSERVATION_TIMEOUT')
def safe_tree_inventory(root):
 rows={}
 for p in sorted(Path(root).rglob('*')):
  s=p.lstat()
  if s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or os.listxattr(p,follow_symlinks=False) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink==1):raise anchor.Refused('TEST_TREE_DRIFT')
  rows[str(p.relative_to(root))]={'dev':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'type':'directory' if p.is_dir() else 'file','sha256':anchor.digest(p.read_bytes()) if p.is_file() else None}
 return rows
def remove_test_tree(root,identity,rows):
 root=Path(root);s=root.lstat()
 if (s.st_dev,s.st_ino)!=identity or safe_tree_inventory(root)!=rows:raise anchor.Refused('TEST_TREE_IDENTITY')
 for name,row in sorted(rows.items(),key=lambda x:len(Path(x[0]).parts),reverse=True):
  p=root/name
  if row['type']=='directory':p.rmdir()
  else:p.unlink()
 root.rmdir();fd=os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def execute(capsule,worker_b,interpreter,interpreter_sha256,transaction):
 if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode or capsule.get('profile')!='validation' or not anchor.tx(transaction):raise anchor.Refused('ROOT_VALIDATION_ONLY')
 fd=anchor.trusted_program(interpreter,interpreter_sha256);os.close(fd)
 os.umask(0o077);p=manager.profile('validation');root=Path(p['root']);unitdir=Path(p['unitdir']);mainpath=unitdir/host.VALIDATION_MAIN;consumer=unitdir/p['consumer']
 protected=[root,Path(host.VALIDATION_PAYLOAD),mainpath,consumer,*[unitdir/n for n in manager.templates('validation','0'*64,interpreter)],unitdir/'sysinit.target.wants'/p['anchor'],unitdir/'timers.target.wants'/p['watch']]
 if any(x.exists() or x.is_symlink() for x in protected):raise anchor.Refused('PREEXISTING_VALIDATION_PATH')
 audit=[];m=manager.Manager('validation',audit.append,lambda:None);original={r:m.show(r) for r in ('anchor','watch','consumer')}
 if any(x['LoadState']!='not-found' or x['ActiveState']!='inactive' for x in original.values()):raise anchor.Refused('PREEXISTING_VALIDATION_UNIT')
 if host.VALIDATION_MAIN not in m.call(('show','--property=Id','--',host.VALIDATION_MAIN)):raise anchor.Refused('MAIN_IDENTITY')
 if 'LoadState=not-found' not in m.call(('show','--property=LoadState','--',host.VALIDATION_MAIN)):raise anchor.Refused('MAIN_PRESTATE')
 manager.no_foreign_reload(m.call(('show','--property=Id,NeedDaemonReload','--','*')),set())
 result={'schema':1,'transaction':transaction,'status':'INCOMPLETE','checks':[],'cleanup_errors':[],'production_actions':False};s=j0=j1=installation=i=None;consumer_id=None;root_identity=None
 evidence=Path('/var/lib')/('tu1nz-v11-validation-evidence-'+transaction[4:]);evidence.mkdir(mode=0o700)
 def mark(name):result['checks'].append(name)
 def alarm(signum,frame):raise ValidationTimeout('ROOT_TEST_TIMEOUT')
 old_handlers={sig:signal.signal(sig,alarm) for sig in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT)};signal.alarm(240)
 try:
  consumer_id=exclusive_file(consumer,b'[Service]\nType=oneshot\nExecStart=/usr/bin/true\n',0o644);m.action('daemon-reload')
  def root_created(identity):
   nonlocal root_identity
   root_identity=identity;CREATION_HOOK(root,identity)
  phase0.prepare(root,capsule['anchor'],[capsule['worker'],worker_b],interpreter,interpreter_sha256,list(host.VALIDATION_TARGETS),validation=True,created=root_created)
  z=root.stat();root_identity=(z.st_dev,z.st_ino);s=anchor.Store(root,validation=True);j0=Journal(root/'phase0-journal',create=True)
  m=manager.Manager('validation',s.record,s.close_fence);installation=install.Install(s,j0,install.file_backend('validation'),m,'validation')
  installation.run();installation.verify_start();installation.run();mark('PHASE0_INSTALLED_LOADED_IDEMPOTENT')
  initial={name:anchor.digest(s.read(name,0o500 if name.endswith('.py') else 0o400)) for name in ('anchor.py','base.json','slot-A.py','slot-A.json')}
  s.publish_slot('B',worker_b);mark('AB_SWITCH_AND_PREVIOUS_RETAINED')
  # Explicit fault injection is restricted to the new validation slot inode.
  f=os.open('slot-B.py',os.O_WRONLY|os.O_NOFOLLOW,dir_fd=s.fd)
  try:os.ftruncate(f,0);os.write(f,b'corrupted test slot\n');os.fsync(f)
  finally:os.close(f)
  if s.choose()['slot']!='A':raise anchor.Refused('FALLBACK')
  f=os.open('slot-B.py',os.O_WRONLY|os.O_NOFOLLOW,dir_fd=s.fd)
  try:
   os.ftruncate(f,0)
   with os.fdopen(f,'wb',closefd=False) as out:out.write(worker_b);out.flush();os.fsync(f)
  finally:os.close(f)
  s.slot('B',anchor.digest(worker_b));mark('CORRUPT_NEW_SLOT_FALLBACK')
  f=host.ValidationFiles();j1=Journal(root/'publication',create=True);ph=host.Phase1Host(s,'validation');i=phase1.Installer(s,f,j1,ph)
  before=f.snapshot(f.targets,f.directories)
  source={host.VALIDATION_TARGETS[0]:b'import time\ntime.sleep(120)\n',host.VALIDATION_TARGETS[1]:b'{"validation":true}\n',host.VALIDATION_TARGETS[2]:('[Service]\nType=simple\nPrivateNetwork=yes\nNoNewPrivileges=yes\nExecStart='+interpreter+' -I -B '+host.VALIDATION_TARGETS[0]+'\n').encode()}
  candidates={path:{'bytes':data,'sha256':anchor.digest(data),'mode':0o500 if path.endswith('.py') else 0o644,'uid':0,'gid':0} for path,data in source.items()}
  i.start(transaction,candidates,before);mark('PHASE1_PUBLISHED_WITH_VERIFIED_BASE')
  m.call(('start','--',host.VALIDATION_MAIN));m.call(('kill','--kill-whom=all','--signal=SIGKILL','--',host.VALIDATION_MAIN));mark('MAIN_WORKER_KILLED')
  m.action('start','watch')
  wait_for(lambda:any(r['event'].get('operation')=='validation_pause' for r in s.journal()[0]),45)
  m.call(('kill','--kill-whom=all','--signal=SIGKILL','--',p['anchor']));mark('ANCHOR_KILLED_DURING_ROLLBACK')
  wait_for(lambda:s.exists('terminal.json'),75);wait_for(lambda:m.show('anchor')['ActiveState']=='inactive',15)
  h=host.RootHost(s,'validation');phase=anchor.parse(s.read('phase1.json',0o600));h.verify_rollback(phase);h.no_worker();h.verify_base()
  if not s.closed() or m.show('watch')['ActiveState']!='inactive':raise anchor.Refused('TERMINAL_NOT_QUIESCENT')
  for name,want in initial.items():
   if anchor.digest(s.read(name,0o500 if name.endswith('.py') else 0o400))!=want:raise anchor.Refused('BASE_CHANGED')
  mark(anchor.TERMINAL)
  m.action('start','anchor');mark('FRESH_BOOT_ENTRY_REVERIFIED_TERMINAL')
  m.call(('start','--',p['consumer']))
  execution=m.call(('show','--property=ExecMainStartTimestampMonotonic,MainPID','--',p['consumer']))
  if 'ExecMainStartTimestampMonotonic=0' not in execution or 'MainPID=0' not in execution:raise anchor.Refused('CONSUMER_STARTED')
  mark('CONSUMER_START_BLOCKED')
  decommission.plan(s,h);decommission.execute_validation(s,installation,m);mark('SEPARATE_DECOMMISSION_VERIFIED')
  result['status']='PASSED'
 except BaseException as error:result['error']=type(error).__name__;result['error_code']=str(error) if str(error).replace('_','').isalnum() and len(str(error))<100 else 'REDACTED_EXCEPTION'
 finally:
  signal.alarm(0)
  # External controller remains alive after either worker and never deletes a
  # pre-existing path. Cleanup is independent of the anchor executable.
  def attempt(name,fn):
   try:fn()
   except BaseException as e:result['cleanup_errors'].append({'step':name,'error':type(e).__name__})
  if s:
   attempt('close_fence',lambda:s.stop('VALIDATION_FINISHED'))
  for role in ('watch','anchor'):
   def stop(role=role):
    if m.show(role)['ActiveState']!='inactive':m.action('stop',role)
   attempt('stop_'+role,stop)
  if i and 'SEPARATE_DECOMMISSION_VERIFIED' not in result['checks']:
   def rollback():
    if s.exists('phase1.json'):i.recover(anchor.parse(s.read('phase1.json',0o600)))
   attempt('phase1_rollback',rollback)
  if installation and 'SEPARATE_DECOMMISSION_VERIFIED' not in result['checks']:attempt('phase0_decommission',lambda:decommission.execute_validation(s,installation,m))
  if consumer_id:attempt('remove_consumer',lambda:remove_exact(consumer,consumer_id))
  # No state writes through the soon-to-be-removed base after final reload.
  final_manager=manager.Manager('validation',audit.append,lambda:None)
  attempt('final_reload',lambda:final_manager.action('daemon-reload'))
  def verify_units():
   final={r:final_manager.show(r) for r in original}
   if any(decommission.normalized(final[r])!=decommission.normalized(original[r]) for r in original):raise anchor.Refused('FINAL_UNIT_DRIFT')
   if 'LoadState=not-found' not in final_manager.call(('show','--property=LoadState','--',host.VALIDATION_MAIN)):raise anchor.Refused('MAIN_REMAINS')
  attempt('final_units',verify_units)
  if j1:j1.close()
  if j0:j0.close()
  if s:s.close()
  if root_identity and not result['cleanup_errors']:
   rows=safe_tree_inventory(root);exclusive_file(evidence/'test-tree-manifest.json',anchor.encode(rows),0o600);attempt('remove_test_base',lambda:remove_test_tree(root,root_identity,rows))
  for sig,handler in old_handlers.items():signal.signal(sig,handler)
  if result['cleanup_errors']:result['status']='CLEANUP_FAILED'
  result['original_test_scope_restored']=not result['cleanup_errors'] and all(not x.exists() and not x.is_symlink() for x in protected)
  if not result['original_test_scope_restored']:result['status']='CLEANUP_FAILED'
  result['audit_sha256']=anchor.digest(anchor.encode(audit));exclusive_file(evidence/'manifest.json',anchor.encode(result),0o600)
  print(anchor.encode({'evidence':str(evidence),'manifest_sha256':anchor.digest(anchor.encode(result)),**result}).decode(),end='')
 return 0 if result['status']=='PASSED' and result['original_test_scope_restored'] else 1
