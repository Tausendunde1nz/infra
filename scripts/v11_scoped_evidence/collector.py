"""Fixed, read-only Trendwatch/Agentmode evidence. No private payload export.
Production execution requires a hash-verified root staging copy. No network calls.
"""
import hashlib,json,os,re,signal,stat,struct,subprocess,sys,time
from pathlib import Path
SOURCE='/usr/local/bin/trendwatch_post.sh'
SOURCE_SHA='467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264'
SERVICES=tuple('trendwatch2-'+x+'.service' for x in ('morning','midday','afternoon','evening'))+('trendwatch-fetch.service',)
TIMERS=tuple(x.replace('.service','.timer') for x in SERVICES[:4])
UNITS=SERVICES+TIMERS+('tu1nz_agentmode.service',)
FILES=(SOURCE,'/usr/local/bin/clone_trendwatch.sh','/usr/local/bin/systemstatus_probe_trendwatch.sh',
 '/usr/local/bin/trendwatch_daily_post.sh','/usr/local/bin/trendwatch_fetch.sh',
 '/usr/local/bin/trendwatch_post.sh.bak.2025-11-28-190755','/usr/local/bin/trendwatch_post.sh.bak_2025-11-30',
 '/usr/local/bin/trendwatch_compose_from_json.sh','/usr/local/bin/tw_fetch.js',
 '/etc/t1nz/trendwatch.env','/etc/t1nz/trendwatch_demo2.env','/etc/t1nz/trendwatch_post.conf',
 '/etc/t1nz/trendwatch_rank.conf','/etc/t1nz/trendwatch_sources.env',
 '/etc/t1nz/backup_2025-11-02_08-57/trendwatch_post.conf',
 '/etc/t1nz/backup_2025-11-02_08-57/notify.conf',
 '/etc/t1nz/backup_2025-11-02_08-57/trendwatch_rank.conf',
 '/etc/tu1nz/trendwatch.env','/etc/tu1nz/trendwatch_post.conf','/etc/tu1nz/trendwatch_sources.env',
 '/etc/tu1nz/trendwatch_sources.env.bak_2025-11-09T20:21:35+00:00')
UNIT_FILES=tuple('/etc/systemd/system/'+u for u in UNITS)+tuple(
 '/etc/systemd/system/trendwatch-fetch.service.d/'+x for x in ('10-perms.conf','20-compose.conf','20-env.conf','20-output.conf'))
PROPS='Id,User,Group,ActiveState,SubState,InvocationID,MainPID,FragmentPath,DropInPaths,EnvironmentFiles,Environment,LoadCredential,LoadCredentialEncrypted,ExecStart,ExecStartPre,ExecStartPost,TriggeredBy,UnitFileState,NextElapseUSecMonotonic,NeedDaemonReload'
class Refused(RuntimeError):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n'
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def acl(fd):
 result={}
 for key in ('system.posix_acl_access','system.posix_acl_default'):
  try:b=os.getxattr(fd,key)
  except OSError as e:
   if e.errno in (61,95):continue
   raise
  if len(b)<4 or struct.unpack('<I',b[:4])[0]!=2 or (len(b)-4)%8:raise Refused('ACL_FORMAT')
  entries=[]
  for tag,perm,uid in struct.iter_unpack('<HHI',b[4:]):
   if tag not in (1,2,4,8,16,32) or perm>7:raise Refused('ACL_FORMAT')
   entries.append({'tag':tag,'permissions':perm,'id':uid})
  result[key]=entries
 return result

def open_path(path):
 p=Path(path)
 if not p.is_absolute() or '..' in p.parts:raise Refused('PATH')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in p.parts[1:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  return os.open(p.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0),dir_fd=fd)
 finally:os.close(fd)

def read_file(path,limit=2_000_000,after_read=None):
 fd=open_path(path)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno())
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise Refused('INPUT_TYPE_LINK_OR_SIZE')
  access=acl(f.fileno());b=f.read(limit+1)
  if after_read:after_read()
  z=os.fstat(f.fileno())
  if identity(a)!=identity(z) or len(b)>limit:raise Refused('INPUT_CHANGED')
  # Reopen through the guarded path to detect rename replacement as well.
  check=open_path(path)
  try:
   if identity(os.fstat(check))!=identity(z):raise Refused('PATH_CHANGED')
  finally:os.close(check)
 return b,{'uid':a.st_uid,'gid':a.st_gid,'mode':oct(stat.S_IMODE(a.st_mode)),
 'inode':a.st_ino,'device':a.st_dev,'type':'regular','bytes':len(b),'sha256':digest(b),'acl':access}

def path_references(data,paths):
 return [p for p in paths if re.search(rb'(?<![A-Za-z0-9_./:@+-])'+re.escape(p.encode())+rb'(?![A-Za-z0-9_./:@+-])',data)]

def summarize(data,token):
 if not isinstance(data,bytes) or not isinstance(token,bytes) or not token:raise Refused('INPUT')
 refs=path_references(data,FILES)
 return {'exposed_token_reference':token in data,'consumer_path_references':refs,
 'telegram_api_reference':b'api.telegram.org' in data,
 'credential_directive':b'LoadCredential' in data,'environment_reference':b'EnvironmentFile' in data,
 'migration':'REPLACE_EXPOSED_REFERENCE' if token in data else ('REVIEW_CALLER' if refs else 'NO_DIRECT_REFERENCE_PROVEN')}

def unit_command(unit):
 if unit not in UNITS:raise Refused('UNIT_SCOPE')
 r=subprocess.run(['/usr/bin/systemctl','show','--property='+PROPS,'--',unit],stdin=subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=10)
 if r.returncode or r.stderr or len(r.stdout)>262144:raise Refused('SYSTEMD_READ_FAILED')
 return r.stdout

def unit_record(unit,data,token):
 lines=data.decode('utf-8').splitlines();props={}
 for line in lines:
  if '=' not in line:raise Refused('UNIT_FORMAT')
  k,v=line.split('=',1)
  if k in props or k not in PROPS.split(','):raise Refused('UNIT_FORMAT')
  props[k]=v
 if props.get('Id')!=unit:raise Refused('UNIT_IDENTITY')
 out={'unit':unit,'references':summarize(data,token),'properties_sha256':digest(data),'scope_complete':True}
 for key in ('FragmentPath','DropInPaths'):
  if any(v not in UNIT_FILES for v in props.get(key,'').split()):out['scope_complete']=False
 for key in ('EnvironmentFiles','LoadCredential','LoadCredentialEncrypted'):
  paths=re.findall(r'/etc/(?:t1nz|tu1nz)/[A-Za-z0-9_./:@+-]+',props.get(key,''))
  if any(v not in FILES for v in paths):out['scope_complete']=False
  if props.get(key) and not paths:out['scope_complete']=False
 for k,allowed in [('ActiveState',{'active','inactive','failed','activating','deactivating','reloading'}),('NeedDaemonReload',{'yes','no'}),('UnitFileState',{'enabled','disabled','static','indirect','masked','enabled-runtime','linked','linked-runtime','alias','generated','transient','not-found',''})]:
  v=props.get(k,'')
  if k=='ActiveState' and v not in allowed:raise Refused('UNIT_STATE')
  out[k]=v if v in allowed else 'UNRECOGNIZED'
 for k in ('User','Group'):
  v=props.get(k,'');out[k]=v if v in ('','root','chatops','tu1nz-trendwatch') else 'OTHER_IDENTITY'
 out['MainPID']=int(props['MainPID']) if re.fullmatch('[0-9]{1,10}',props.get('MainPID','')) else None
 inv=props.get('InvocationID','');out['InvocationID']=inv if re.fullmatch('[a-f0-9]{32}',inv) else None
 for k in ('FragmentPath','DropInPaths','EnvironmentFiles','LoadCredential','LoadCredentialEncrypted','ExecStart','ExecStartPre','ExecStartPost','Environment'):
  value=props.get(k,'').encode();out[k]={'present':bool(value),'token_reference':token in value,'known_path_references':path_references(value,FILES+UNIT_FILES)}
 return out

def lock_metadata(path):
 # Never open or read lock contents, never acquire or release a service lock.
 p=Path(path)
 if path!='/run/tu1nz-agentmode/control-observer.lock':raise Refused('LOCK_SCOPE')
 try:fd=open_path(path)
 except FileNotFoundError:return {'path':path,'absent':True}
 try:s=os.fstat(fd);access=acl(fd)
 finally:os.close(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise Refused('LOCK_TYPE')
 key='%02x:%02x:%d'%(os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)
 found=[]
 for line in Path('/proc/locks').read_text().splitlines():
  fields=line.split()
  if key in fields:found.append({'kernel_lock_present':True})
 return {'path':path,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'inode':s.st_ino,'kernel_locks':found,'acl':access}

def transaction_metadata():
 # Names and metadata only. No state contents, no APE/approval traversal.
 out=[]
 for p in Path('/var/lib').iterdir():
  if not re.fullmatch(r'(?:tu1nz-privileged-v11-[a-f0-9]{32}|\.tu1nz-privileged-v11-[a-f0-9]{32}-bootstrap-[a-f0-9]{32})',p.name):continue
  s=p.lstat();out.append({'path':str(p),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),
   'type':'directory' if stat.S_ISDIR(s.st_mode) else 'other','requires_reconciliation':True})
  if len(out)>128:raise Refused('TRANSACTION_COUNT')
 return out

def atomic(directory,name,value):
 if not re.fullmatch(r'[a-z][a-z0-9_-]*\.json',name):raise Refused('OUTPUT_NAME')
 directory=Path(directory);s=directory.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700 or directory.is_symlink():raise Refused('OUTPUT_DIRECTORY')
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 tmp='.'+name+'-'+os.urandom(8).hex()
 try:
  f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  with os.fdopen(f,'wb') as o:os.fchmod(o.fileno(),0o600);o.write(encode(value));o.flush();os.fsync(o.fileno())
  os.link(tmp,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(tmp,dir_fd=fd);os.fsync(fd)
 finally:
  try:os.unlink(tmp,dir_fd=fd)
  except FileNotFoundError:pass
  os.close(fd)

def collect(out,reader=read_file,runner=unit_command,locks=lock_metadata,transactions=transaction_metadata):
 manifest={'schema':1,'status':'INCOMPLETE','sections':[],'raw_payloads_saved':False};token=None
 def section(name,fn):
  start=time.monotonic_ns()
  try:
   value=fn();status='ERROR' if isinstance(value,dict) and value.get('scope_complete') is False else 'OK';error='UnreviewedReference' if status=='ERROR' else None
  except BaseException as e:
   value={'error_class':type(e).__name__};status='ERROR';error=type(e).__name__
   if isinstance(e,(KeyboardInterrupt,SystemExit)):raise
  atomic(out,name,value)
  manifest['sections'].append({'section':name,'status':status,'error_class':error,'start_ns':start,'end_ns':time.monotonic_ns(),'sha256':digest(encode(value))})
 try:
  raw,_=reader(SOURCE)
  if digest(raw)!=SOURCE_SHA:raise Refused('SOURCE_DRIFT')
  tokens=set(re.findall(rb'\b[0-9]{6,15}:[A-Za-z0-9_-]{30,60}\b',raw))
  if len(tokens)!=1:raise Refused('SOURCE_TOKEN_COUNT')
  token=next(iter(tokens));del raw,tokens
  for i,path in enumerate(FILES+UNIT_FILES):
   def file_record(path=path):
    try:data,meta=reader(path)
    except FileNotFoundError:return {'path':path,'status':'ABSENT','consumer_activity':'NOT_PROVEN'}
    return {'path':path,'metadata':meta,'references':summarize(data,token),'consumer_activity':'CORRELATE_WITH_EFFECTIVE_UNITS'}
   section('file-%03d.json'%i,file_record)
  for i,u in enumerate(UNITS):section('unit-%03d.json'%i,lambda u=u:unit_record(u,runner(u),token))
  section('agentmode-lock.json',lambda:locks('/run/tu1nz-agentmode/control-observer.lock'))
  section('transaction-metadata.json',transactions)
  manifest['status']='COMPLETE' if all(s['status']=='OK' for s in manifest['sections']) else 'INCOMPLETE'
 except BaseException as e:manifest['fatal_error_class']=type(e).__name__
 finally:
  token=None;atomic(out,'manifest.json',manifest)
 return manifest

def main():
 if os.geteuid()!=0 or len(sys.argv)!=1:raise Refused('ROOT_NO_ARGUMENTS')
 stage=Path(__file__).parent;root=stage.parent
 if stage.name!='staging' or root.parent!=Path('/var/lib') or not re.fullmatch('tu1nz-v11-scoped-evidence-[a-z0-9_]+',root.name):raise Refused('STAGING_PATH')
 for p in (stage,root):
  s=p.lstat()
  if s.st_uid!=0 or s.st_mode&0o022 or p.is_symlink():raise Refused('STAGING_OWNER')
 out=root/'results';os.mkdir(out,0o700)
 def interrupted(sig,frame):raise KeyboardInterrupt()
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 m=collect(out)
 # Keep the authoritative reduced records 0600; export only identical sanitized data.
 export=root/'redacted';os.mkdir(export,0o700)
 for f in out.iterdir():
  value=json.loads(f.read_bytes());atomic(export,f.name,value)
  target=export/f.name;os.chown(target,0,1001);os.chmod(target,0o640)
 os.chown(export,0,1001);os.chmod(export,0o750)
 print('SCOPED_EVIDENCE_STATUS='+m['status'],flush=True)
 return 0 if m['status']=='COMPLETE' else 2
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:print('SCOPED_EVIDENCE_FATAL:'+type(e).__name__,file=sys.stderr);raise SystemExit(3)
