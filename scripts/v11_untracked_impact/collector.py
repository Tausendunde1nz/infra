"""Metadata-only classification helpers. Never executes or imports an inspected file."""
import hashlib,os,pathlib,re,stat,struct
LIMIT=8*1024*1024
class Refused(RuntimeError):pass

def acl(raw):
 if len(raw)<4 or (len(raw)-4)%8 or struct.unpack('<I',raw[:4])[0]!=2:raise Refused('ACL_FORMAT')
 names={1:'user_obj',2:'user',4:'group_obj',8:'group',16:'mask',32:'other'};rows=[]
 for off in range(4,len(raw),8):
  tag,perm,ident=struct.unpack('<HHI',raw[off:off+8])
  if tag not in names or perm>7:raise Refused('ACL_ENTRY')
  rows.append({'tag':names[tag],'permissions':perm,'id':None if ident==0xffffffff else ident})
 mask=next((x['permissions'] for x in rows if x['tag']=='mask'),7)
 for x in rows:x['effective_permissions']=x['permissions']&mask if x['tag'] in ('user','group','group_obj') else x['permissions']
 return rows

def categories(name,mode):
 if stat.S_ISLNK(mode):return ['symlink']
 if '/__pycache__/' in name and name.endswith('.pyc'):return ['cache']
 if name.endswith(('.pid','.lock')) or name in ('last_sync.ok','monitor_last.txt'):return ['runtime_status']
 if name.endswith(('.tar.gz','.bak','.before','.paused')) or '.bak_' in name:return ['backup','operator_state']
 if name.endswith(('.service','.timer','.socket','.path','.conf','.py','.sh')) or bool(mode&0o111):return ['possible_source_or_configuration']
 if name.startswith(('analysis/','rebaseline_2026/')):return ['operator_state']
 if any(x in name for x in ('checksum','integrity','filelist')):return ['runtime_status','operator_state']
 return ['operator_state']

def inventory_one(root,rel):
 parts=pathlib.PurePosixPath(rel).parts
 if not parts or rel.startswith('/') or any(x in ('.','..','.git') for x in parts):raise Refused('PATH_SCOPE')
 root=pathlib.Path(root);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parents=[]
  for part in parts[:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
   st=os.fstat(fd);parents.append({'component':part,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))})
  st=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False);kind='regular' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'special'
  r={'path':rel,'type':kind,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),'size':st.st_size,'inode':st.st_ino,'nlink':st.st_nlink,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'parents':parents,'categories':categories(rel,st.st_mode),'sha256':None,'hash_reason':None,'acls':{},'relevant_xattrs':[]}
  p=root/rel
  try:
   for key in os.listxattr(p,follow_symlinks=False):
    if key.startswith('system.posix_acl_'):r['acls'][key]=acl(os.getxattr(p,key,follow_symlinks=False))
    elif key.startswith(('security.','trusted.')):r['relevant_xattrs'].append(key)
  except OSError as e:r['xattr_error']=type(e).__name__
  if kind=='symlink':r['link_target']=re.sub(r'(://)[^/@]+@',r'\1[REDACTED]@',os.readlink(parts[-1],dir_fd=fd));r['hash_reason']='SYMLINK_NOT_FOLLOWED'
  elif kind!='regular':r['hash_reason']='NOT_REGULAR'
  elif st.st_nlink!=1:r['hash_reason']='HARDLINK_NOT_OPENED'
  elif st.st_size>LIMIT:r['hash_reason']='SIZE_LIMIT'
  elif 'runtime_status' in r['categories']:r['hash_reason']='POTENTIALLY_ACTIVE_RUNTIME_NOT_OPENED'
  else:
   f=None
   try:
    f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);a=os.fstat(f)
    if not stat.S_ISREG(a.st_mode) or (a.st_dev,a.st_ino)!=(st.st_dev,st.st_ino):raise Refused('OPEN_RACE')
    h=hashlib.sha256();total=0
    while True:
     b=os.read(f,65536)
     if not b:break
     total+=len(b)
     if total>LIMIT:raise Refused('READ_LIMIT')
     h.update(b)
    z=os.fstat(f);end=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
    def sig(x):return(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if sig(a)!=sig(z) or sig(a)!=sig(end):raise Refused('CONTENT_RACE')
    r['sha256']=h.hexdigest();r['hash_reason']='STABLE_REGULAR_BYTES_ONLY'
   except (OSError,Refused) as e:r['hash_reason']=type(e).__name__
   finally:
    if f is not None:os.close(f)
  return r
 finally:os.close(fd)

def dimensions(tracked,entries,contract,writers=False):
 if tracked not in ('PASS','FAIL','UNPROVEN') or contract not in ('EXPECTED_ROOT_CONTROLLED','EXPECTED_CHATOPS_CONTROLLED','CONTRADICTORY','UNPROVEN'):raise Refused('STATUS')
 kinds={x['impact'] for x in entries}
 if not kinds<= {'BENIGN','EXECUTION_RELEVANT','SECURITY_RELEVANT','UNKNOWN'}:raise Refused('IMPACT')
 impact=next((v for v in ('SECURITY_RELEVANT','EXECUTION_RELEVANT','UNKNOWN','BENIGN') if v in kinds),'BENIGN')
 if writers:overall='ACTIVE_WRITER_OR_TRANSACTION'
 elif tracked=='FAIL':overall='LOCAL_CHECKOUT_DRIFT'
 elif tracked!='PASS':overall='CHECKOUT_CONTRACT_UNPROVEN'
 elif any(x.get('active_shadow_risk') is True for x in entries):overall='TRUSTED_TRACKED_BUT_EXECUTION_SHADOW_RISK'
 elif tracked!='PASS' or contract in ('UNPROVEN','CONTRADICTORY') or 'UNKNOWN' in kinds:overall='CHECKOUT_CONTRACT_UNPROVEN'
 elif kinds=={'BENIGN'} or not kinds:overall='TRUSTED_CLEAN_TRACKED_WITH_BENIGN_UNTRACKED_STATE'
 elif all(x.get('controlled') is True for x in entries if x['impact']!='BENIGN'):overall='TRUSTED_TRACKED_WITH_CONTROLLED_OPERATIONAL_STATE'
 else:overall='CHECKOUT_CONTRACT_UNPROVEN'
 return {'TRACKED_INTEGRITY':tracked,'UNTRACKED_IMPACT':impact,'CHECKOUT_CONTRACT':contract,'overall':overall}

# The remaining privileged scope is literal and pinned; no user-supplied paths.
import signal,time,json
ROOT='/opt/tu1nz_repos/control'
METADATA_PATHS=('analysis/security_incident_2026-08-25/.token_rotation.lock', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_INCIDENT_2026-08-25.diagnose', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_APPLY_RESULT.json', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_B_REAPPLY_RESULT.json', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_CONTAINMENT_2026-08-25.diagnose', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_FINAL_2026-08-25.diagnose', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_STATE_BEFORE_2026-08-25.diagnose', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_TEST_RESULT.json', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_apply_tokens.py', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_chatops.crontab.before', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_chatops.crontab.paused', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_identify.py', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_reapply_bot_b.py', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_send_tests.py', 'analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_validate_tokens.py', 'analysis/security_incident_2026-08-25/cron.before', 'analysis/security_incident_2026-08-25/cron.paused', 'scripts/__pycache__/tu1nz_adult_public_community_health_contract.cpython-312.pyc')
ALL_NAMES=('.r28r4-control-payload-clean.tar.gz', '.token_rotation.lock', 'TU1NZ_SECURITY_INCIDENT_2026-08-25.diagnose', 'TU1NZ_SECURITY_S3_APPLY_RESULT.json', 'TU1NZ_SECURITY_S3_B_REAPPLY_RESULT.json', 'TU1NZ_SECURITY_S3_CONTAINMENT_2026-08-25.diagnose', 'TU1NZ_SECURITY_S3_FINAL_2026-08-25.diagnose', 'TU1NZ_SECURITY_S3_STATE_BEFORE_2026-08-25.diagnose', 'TU1NZ_SECURITY_S3_TEST_RESULT.json', 'TU1NZ_SECURITY_S3_apply_tokens.py', 'TU1NZ_SECURITY_S3_chatops.crontab.before', 'TU1NZ_SECURITY_S3_chatops.crontab.paused', 'TU1NZ_SECURITY_S3_identify.py', 'TU1NZ_SECURITY_S3_reapply_bot_b.py', 'TU1NZ_SECURITY_S3_send_tests.py', 'TU1NZ_SECURITY_S3_validate_tokens.py', '_filelist_reference.txt', '_filelist_reference.txt.bak_20260215T082155Z', '_tg_direct_callers_ACTIVE.txt', '_tg_wrapper_users_ACTIVE.txt', '_unitlist_tu1nz.txt', 'aide-daily.service', 'aide-daily.timer', 'checksums.txt', 'checksums_current.txt', 'checksums_reference.sha256', 'checksums_reference.txt', 'codex-queue.service', 'codex-queue.timer', 'cron.before', 'cron.paused', 'doc-trigger.service', 'doc-trigger.timer', 'docker_inspect_n8n_before.json', 'docker_ps_before.txt', 'docs-upload.service', 'docs-upload.timer', 'emoji_map.sed', 'encrypted_drive_backup', 'guard_units.txt', 'health_units.txt', 'integrity_baseline.sha256', 'integrity_reference.sha256', 'integrity_reference.txt', 'key_files_before.txt', 'last_sync.ok', 'lock_units.txt', 'monitor_last.txt', 'n8n.conf.before', 'opt_root.txt', 'permissions_before.txt', 'ss_before.txt', 'systemd_system.txt', 'test_adult_commercial_final_first_start.cpython-312.pyc', 'test_adult_commercial_first_start.cpython-312.pyc', 'test_adult_commercial_host_access_design.cpython-312.pyc', 'test_adult_commercial_installation_authorization.cpython-312.pyc', 'test_adult_commercial_installation_preflight.cpython-312.pyc', 'test_adult_commercial_m4_26.cpython-312.pyc', 'test_adult_commercial_m4_27.cpython-312.pyc', 'test_adult_commercial_m4_28.cpython-312.pyc', 'test_adult_commercial_m4_29.cpython-312.pyc', 'test_adult_commercial_readiness.cpython-312.pyc', 'test_adult_commercial_s0_installation_design.cpython-312.pyc', 'test_adult_commercial_s0_stopped_installation.cpython-312.pyc', 'test_adult_commercial_s0_unit_refresh.cpython-312.pyc', 'test_adult_commercial_s3_1_bootstrap_ownership_control.cpython-312.pyc', 'test_adult_commercial_s3_2_rolling_debug_control.cpython-312.pyc', 'test_adult_commercial_s3_server_staging_control.cpython-312.pyc', 'test_adult_commercial_s4_extended_staging_control.cpython-312.pyc', 'test_adult_commercial_s5_s6_offline_staging.cpython-312.pyc', 'test_adult_commercial_s7_public_soft_launch.cpython-312.pyc', 'test_adult_restore_verify.cpython-312.pyc', 'test_adult_s0_deployment_readiness.cpython-312.pyc', 'test_adult_s1_runtime.cpython-312.pyc', 'test_m4_29_2_agentmode_maintenance.cpython-312.pyc', 'timers.txt', 'trendwatch_units.txt', 'tu1nz-docspush-watchdog.service', 'tu1nz-docspush-watchdog.timer', 'tu1nz-docspush.service', 'tu1nz-docspush.timer', 'tu1nz-git-sync.service', 'tu1nz-git-sync.timer', 'tu1nz-integrity.service', 'tu1nz-integrity.timer', 'tu1nz_adult_commercial_s0_first_start.cpython-312.pyc', 'tu1nz_adult_commercial_s0_manifest.cpython-312.pyc', 'tu1nz_adult_public_community_health_contract.cpython-312.pyc', 'tu1nz_adult_public_s10_1_health.cpython-312.pyc', 'tu1nz_adult_public_s10_2d_aggregate_contract.cpython-312.pyc', 'tu1nz_adult_public_s10_2d_health_gate.cpython-312.pyc', 'tu1nz_adult_public_s10_2d_state_reconcile.cpython-312.pyc', 'tu1nz_adult_staging_manifest.cpython-312.pyc', 'tu1nz_units.txt', 'unit_files.txt', 'units_active.txt', 'usr_local_bin.txt', 'validation.pid')
HELPERS=('/usr/local/bin/aide_daily.sh','/usr/local/bin/backup_notify.sh','/usr/local/bin/doku_agent_health.sh','/usr/local/bin/tu1nz-ape-notify-core','/etc/nginx/sites-available/tu1nz.conf','/etc/nginx/sites-enabled/tu1nz.conf')
class SectionTimeout(RuntimeError):pass
class Interrupted(RuntimeError):pass

def secure_read(path,limit=1024*1024):
 p=pathlib.Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in p.parts[1:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 finally:os.close(fd)
 try:
  a=os.fstat(f)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise Refused('READ_SCOPE')
  b=os.read(f,limit+1);z=os.fstat(f)
  if len(b)!=a.st_size or len(b)>limit or (a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('READ_RACE')
  return b
 finally:os.close(f)

def references(path):
 p=pathlib.Path(path)
 if p.is_symlink():
  target=os.readlink(p);canonical=os.path.normpath(str(p.parent/target))
  if str(p)!='/etc/nginx/sites-enabled/tu1nz.conf' or canonical!='/etc/nginx/sites-available/tu1nz.conf':raise Refused('UNEXPECTED_REFERENCE_SYMLINK')
  return {'path':path,'link_target':canonical,'target_collected_separately':True,'symlink_not_followed_here':True}
 b=secure_read(path);text=b.decode('utf-8',errors='replace');hits=[]
 for i,line in enumerate(text.splitlines(),1):
  names=[name for name in ALL_NAMES if name in line]
  if ROOT in line or 'pandoc_safe' in line or names:
   hits.append({'line':i,'checkout_literal':ROOT in line,'pandoc_safe':'pandoc_safe' in line,'known_names':names,'comment':line.lstrip().startswith('#')})
 return {'path':path,'sha256':hashlib.sha256(b).hexdigest(),'matches':hits,'scope':'REFERENCE_TOKENS_ONLY_NO_CONTENT'}

def git_config(path):
 # Emit names and hashes only; selected known safe.directory values are enough.
 b=secure_read(path,262144);items=[];section=''
 for i,line in enumerate(b.decode('utf-8',errors='replace').splitlines(),1):
  stripped=line.strip()
  if stripped.startswith('['):section=stripped.lower();continue
  if '=' not in stripped:continue
  key,value=stripped.split('=',1);key=key.strip().lower();value=value.strip()
  if section=='[safe]' and key=='directory':items.append({'line':i,'key':'safe.directory','value':value if value in ('*',ROOT) else 'OTHER_PATH_REDACTED','value_sha256':hashlib.sha256(value.encode()).hexdigest()})
  elif any(x in section for x in ('include','core','diff','filter')):items.append({'line':i,'key':'OTHER_RELEVANT_SETTING','value_sha256':hashlib.sha256(value.encode()).hexdigest()})
 return {'path':path,'sha256':hashlib.sha256(b).hexdigest(),'settings':items,'config_not_executed':True}

def writers():
 found=[];incomplete=False;prefix=ROOT+'/'
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  try:
   cwd=os.readlink(p/'cwd');fdpaths=[]
   for f in (p/'fd').iterdir():
    try:
     target=os.readlink(f);m=re.search(r'^flags:\s+([0-7]+)$',(p/'fdinfo'/f.name).read_text(),re.M)
     if m and int(m[1],8)&3 in (1,2) and (target==ROOT or target.startswith(prefix)):fdpaths.append(target)
    except FileNotFoundError:continue
   if cwd==ROOT or cwd.startswith(prefix) or fdpaths:found.append({'pid':int(p.name),'cwd_in_checkout':cwd==ROOT or cwd.startswith(prefix),'writable_paths':fdpaths})
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:incomplete=True
 return {'processes':found,'incomplete':incomplete}

def metadata_without_runtime_read(rel,writer_report):
 if writer_report['incomplete'] or writer_report['processes']:
  raise Refused('WRITER_VIEW_NOT_QUIESCENT')
 return inventory_one(ROOT,rel)

def atomic(directory,name,obj):
 data=json.dumps(obj,sort_keys=True,ensure_ascii=True).encode()+b'\n';tmp=directory/('.'+name+'-'+os.urandom(8).hex())
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
 os.link(tmp,directory/name,follow_symlinks=False);tmp.unlink();fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return hashlib.sha256(data).hexdigest()

def section(out,name,fn,records):
 start=time.monotonic_ns();status='OK';error=None
 try:value=fn()
 except Interrupted:raise
 except BaseException as exc:status='ERROR';error=type(exc).__name__;value={'status':status,'error_class':error}
 digest=atomic(out,name,value);records.append({'section':name,'status':status,'error_class':error,'timeout':error=='SectionTimeout','start_ns':start,'end_ns':time.monotonic_ns(),'sha256':digest})
 return value

def manifest(records,interrupted=False,fatal=None):
 return {'schema':1,'status':'INCOMPLETE' if interrupted or fatal or any(x['status']!='OK' for x in records) else 'COMPLETE','interrupted':interrupted,'fatal_error_class':fatal,'sections':records,'no_live_mutations':True}

def main():
 if os.geteuid()!=0:raise Refused('ROOT_REQUIRED')
 stage=pathlib.Path(__file__).parent;root=stage.parent
 if stage.name!='staging' or root.parent!=pathlib.Path('/var/lib') or not re.fullmatch(r'tu1nz-v11-untracked-evidence-[a-z0-9_]+',root.name):raise Refused('OUTPUT_PATH')
 for p in (root,stage):
  st=p.lstat()
  if p.is_symlink() or st.st_uid!=0 or st.st_mode&0o022 or any('posix_acl' in x for x in os.listxattr(p)):raise Refused('OUTPUT_PERMISSIONS')
 os.umask(0o077);out=root/'results';out.mkdir(mode=0o700);records=[];interrupted=False;fatal=None
 def stop(signum,frame):raise Interrupted()
 def timeout(signum,frame):raise SectionTimeout()
 signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGALRM,timeout)
 def run(name,fn):
  signal.alarm(15)
  try:return section(out,name,fn,records)
  finally:signal.alarm(0)
 try:
  view=run('writers-before.json',writers)
  if 'processes' not in view:view={'incomplete':True,'processes':[]}
  for i,rel in enumerate(METADATA_PATHS):run('metadata-%02d.json'%i,lambda rel=rel:metadata_without_runtime_read(rel,view))
  for i,p in enumerate(HELPERS):run('helper-%02d.json'%i,lambda p=p:references(p))
  for i,p in enumerate(('/root/.gitconfig','/etc/gitconfig')):
   run('git-config-%02d.json'%i,lambda p=p:git_config(p) if pathlib.Path(p).exists() else {'path':p,'absent':True})
  cron=pathlib.Path('/var/spool/cron/crontabs')
  def crons():
   entries=list(cron.iterdir()) if cron.exists() else []
   if len(entries)>32:raise Refused('CRON_COUNT')
   return {'paths':[str(p) for p in sorted(entries) if not p.name.startswith('.')],'scope':'DIRECT_CHILDREN_REFERENCE_ONLY'}
  cr=run('cron-inventory.json',crons)
  for i,p in enumerate(cr.get('paths',[])):run('cron-%02d.json'%i,lambda p=p:references(p))
  run('writers-after.json',writers)
 except Interrupted:interrupted=True
 except BaseException as exc:fatal=type(exc).__name__
 finally:
  signal.alarm(0);signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
  result=manifest(records,interrupted,fatal);result['source_sha256']=hashlib.sha256(secure_read(__file__)).hexdigest()
  atomic(out,'manifest.json',result)
  export=root/'redacted';export.mkdir(mode=0o750);os.chown(export,0,1001);os.chmod(export,0o750)
  for p in out.iterdir():
   if p.name.startswith('.'):continue
   data=secure_read(p);f=export/p.name;fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
   with os.fdopen(fd,'wb') as h:os.fchmod(h.fileno(),0o640);os.fchown(h.fileno(),0,1001);h.write(data);h.flush();os.fsync(h.fileno())
  print(json.dumps({'root':str(root),'status':result['status'],'sections':len(records)}),flush=True)
 return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
