"""One bounded read-only run over pinned archives and their exact live paths."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import grp
import re
import resource
import signal
import stat
import subprocess
from reader_v2_guard import guarded

PREFIX='TU1NZ_BACKUP_NOTIFY_V3='
PROPS=['Id','User','ActiveState','UnitFileState','LoadState','Triggers','TriggeredBy','DropInPaths']

def expired(signum,frame):raise TimeoutError()


def unit_states(names,binding):
 guarded(Path('/usr/bin/systemctl'),binding['systemctl_sha256'],16_000_000,private=False)
 names=sorted(set(names)|{'cron.service'})
 if len(names)>1800 or any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]*\.(service|timer)',n) for n in names):raise ValueError('unit_bounds')
 result={}
 for start in range(0,len(names),80):
  argv=['/usr/bin/systemctl','show','--no-pager']
  for prop in PROPS:argv+=['-p',prop]
  argv+=['--']+names[start:start+80]
  p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,
   cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  if p.returncode or p.stderr or len(p.stdout)>1_000_000:continue
  for block in p.stdout.decode('utf8','strict').strip().split('\n\n'):
   fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
   if fields.get('Id') in names:result[fields['Id']]=fields
 return result


def live_identity(path,expected,uid,gids):
 """No contents exported. Walk by directory descriptors, never follow symlinks."""
 parts=Path(path).parts
 if not path.startswith('/') or '..' in parts or path.endswith('/.env'):raise ValueError('path')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);components=[];unknown=False;influence=False
 try:
  for index,name in enumerate(parts[1:]):
   last=index==len(parts)-2
   child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if last else os.O_DIRECTORY),dir_fd=fd)
   os.close(fd);fd=child;s=os.fstat(fd)
   if last and not stat.S_ISREG(s.st_mode):raise ValueError('type')
   acl=any('posix_acl' in x for x in os.listxattr(fd))
   writable=(s.st_uid==uid and bool(s.st_mode&0o200)) or (s.st_gid in gids and bool(s.st_mode&0o020)) or bool(s.st_mode&0o002)
   # ACLs can grant named-user rights; without decoding report UNKNOWN, never safe.
   unknown|=acl;influence|=writable
   components.append({'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'acl_present':acl,'chatops_write_bits':writable})
  h=hashlib.sha256();total=0;before=os.fstat(fd)
  while True:
   chunk=os.read(fd,65536)
   if not chunk:break
   total+=len(chunk)
   if total>2_000_000:raise ValueError('size')
   h.update(chunk)
  after=os.fstat(fd)
  stable=(before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
  return {'exists':True,'hash_matches':stable and h.hexdigest()==expected,'components':components,
   'chatops_influence':True if influence else 'UNKNOWN' if unknown else False}
 except FileNotFoundError:return {'exists':False,'hash_matches':False,'chatops_influence':'UNKNOWN'}
 except Exception as e:return {'exists':'UNKNOWN','hash_matches':False,'chatops_influence':'UNKNOWN','error_class':type(e).__name__}
 finally:os.close(fd)


def unit_name(path):
 p=Path(path)
 if p.suffix in ('.service','.timer'):return p.name
 if p.suffix=='.conf' and p.parent.name.endswith(('.service.d','.timer.d')):return p.parent.name[:-2]
 return None


def root_context(path,projection,states):
 name=unit_name(path)
 if name:
  state=states.get(name,{})
  enabled=state.get('UnitFileState') in ('enabled','enabled-runtime','linked','linked-runtime','alias')
  active=state.get('ActiveState') in ('active','activating','reloading')
  trigger=any(states.get(t,{}).get('ActiveState')=='active' or states.get(t,{}).get('UnitFileState') in ('enabled','enabled-runtime') for t in state.get('TriggeredBy','').split())
  certainty=bool(state) and state.get('LoadState')=='loaded'
  # Unit overrides and '+' execution prefixes may change privilege; conservative root.
  root=True if state.get('User') in ('','root','0') else 'UNKNOWN'
  return {'path':path,'kind':'SYSTEMD','unit':name,'root':root,
   'active':True if enabled or active or trigger else False if certainty and state.get('UnitFileState')=='masked' else 'UNKNOWN',
   'state':{k:state.get(k,'UNKNOWN') for k in ('LoadState','ActiveState','UnitFileState')},'dropins_present':bool(state.get('DropInPaths'))}
 if projection.get('root_cron'):
  active=states.get('cron.service',{}).get('ActiveState')=='active'
  return {'path':path,'kind':'CRON','root':True,'active':True if active else 'UNKNOWN'}
 if any(x in path for x in ('/cron.','/init.d/','/network/','/NetworkManager/','/apt/','/dpkg/','/kernel/','/initramfs','/system-shutdown/','/system-sleep/')):
  return {'path':path,'kind':'HOOK','root':'UNKNOWN','active':'UNKNOWN'}
 return None


def main(binding,engine,parser):
 if os.geteuid()!=0:return 77
 os.environ.clear();os.environ.update({'PATH':'/usr/bin:/bin','LC_ALL':'C'});os.umask(0o077)
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(150,150));resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
 signal.signal(signal.SIGALRM,expired);signal.alarm(240)
 out={'version':'3.0.0','activation_ready':False,'env_trust':'UNTRUSTED_IN_ALL_ROOT_CONTEXTS','nodes':{},'root_entries':[]}
 try:
  root=Path(binding['archive_root']);known={x['path'] for x in binding['callers']}|{engine.TARGET}
  user=pwd.getpwnam('chatops');gids=set(os.getgrouplist('chatops',user.pw_gid))
  states=unit_states([n for n in (unit_name(p) for p in known) if n],binding)
  source=guarded(root/binding['source_archive'],binding['source_sha256'])
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):out['sinks']=engine.sink_matrix(source,parser)
  out['source_sha256']=binding['source_sha256'];total=0;checked=0;missing=0
  for item in binding['callers']:
   raw=guarded(root/item['archive'],item['sha256']);total+=len(raw);checked+=1
   if total>64*1024*1024:raise ValueError('budget')
   live=live_identity(item['path'],item['sha256'],user.pw_uid,gids)
   if live['exists'] is False:missing+=1;continue
   with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):projection=engine.caller_projection(raw,item['path'],parser,known)
   projection.update(sha256=item['sha256'],live=live,category=item['category'])
   if not live['hash_matches']:projection['unknown']=True
   out['nodes'][item['path']]=projection
   entry=root_context(item['path'],projection,states)
   if entry:out['root_entries'].append(entry)
  # Entries of unsupported activation grammar are explicitly potential roots.
  represented={r['path'] for r in out['root_entries']}
  for path,node in out['nodes'].items():
   if node['category'] in ('systemd','cron','package-hooks','network-hooks','boot-shutdown','additional-hooks','effective-unit') and path not in represented:
    out['root_entries'].append({'path':path,'kind':'UNKNOWN_ENTRY','root':'UNKNOWN','active':'UNKNOWN'})
  out.update(engine.graph_decision(out['nodes'],out['root_entries']))
  out['quarantine']=engine.quarantine_plan(out)
  out['inventory']={'fixed_candidates_checked':checked,'bytes':total,'missing_live_candidates':missing,'new_filesystem_scan':False}
  out['status']='COLLECTED'
 except Exception as e:
  out.update(status='INCOMPLETE',error_class=type(e).__name__,classification='ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN',active_root_call_proved=False,
    classification_basis='PRECAUTIONARY_COLLECTION_FAILURE')
  out['quarantine']=engine.quarantine_plan(out)
 finally:signal.alarm(0)
 # Only fixed paths from pinned bindings, numeric metadata, bounded categories.
 data=json.dumps(out,sort_keys=True)
 if len(data)>7_000_000:
  data=json.dumps({'version':'3.0.0','status':'INCOMPLETE','error_class':'OutputLimit','activation_ready':False})
 print(PREFIX+data)
 return 0 if out.get('status')=='COLLECTED' else 2
