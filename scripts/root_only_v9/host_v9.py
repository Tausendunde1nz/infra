"""Fixed host adapter; only the hash-bound root entrypoint may instantiate it.

No action on import. Every mutation requires an original and candidate record.
No arbitrary path, unit, container, argument or environment is accepted.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import stat
import secrets
import time
from policy_v9 import Refused,DROPIN
from files_v9 import read_file,bytes_of,same_content,same_identity,write_exact,safe_chain
from audit_v9 import socket_identity,fixed_cutover,restore_socket,proc_identity,rollback_postimage
from command_v9 import checked,command
from contracts_v9 import *
from lifecycle_v9 import unit_candidate,Lifecycle,PREFIX
from runtime_v9 import containers,units,clear_clients,protected_services_unchanged,monitoring,digest,long_lived_chatops_contexts
from probes_v9 import fresh_probe,negative_context_probe,extra_gid_interfaces

ROOT=Path('/var/lib/tu1nz-root-only-v9')
PACKAGE=Path('/usr/local/libexec/tu1nz-root-only-v9')
BROKER_ROOT=Path('/var/lib/tu1nz-codex-ops')
MYCB_UNIT='/etc/systemd/system/mychatbuddy-private-alpha.service'
DROPIN_PATH='/etc/systemd/system/docker.socket.d/90-tu1nz-root-only.conf'
BROKER='/usr/local/sbin/tu1nz-codex-ops'
HELPER='/usr/local/sbin/tu1nz-mychatbuddy-lifecycle'
SUDO_PATHS=('/etc/sudoers','/etc/sudoers.d/99-dokuagent-pandoc','/etc/sudoers.d/chatops-nopass')
NEW_SUDO='/etc/sudoers.d/90-tu1nz-codex-ops'
MASK=b'[Unit]\nDescription=TU1NZ security quarantine; original archived privately\nRefuseManualStart=yes\nConditionPathExists=/var/lib/tu1nz-root-only-v9/QUARANTINE_RELEASE_NOT_AUTHORIZED\n[Service]\nType=oneshot\nExecStart=/usr/bin/false\n'
CRON_GUARD=b'# TU1NZ security quarantine. Original archived privately; no automatic reactivation.\n'
NOTIFY_GUARD=b'#!/usr/bin/env -S /usr/bin/python3 -I -S\nraise SystemExit(78)\n'
READ_TARGETS=tuple(sorted(set(SUDO_PATHS+('/etc/group','/etc/gshadow',NEW_SUDO,BROKER,HELPER,MYCB_UNIT,DROPIN_PATH,
 '/usr/lib/systemd/system/docker.socket','/usr/lib/systemd/system/docker.service','/etc/docker/daemon.json')+tuple(QUARANTINE_HASHES)+tuple('/etc/systemd/system/'+n for n in FIXED_UNSAFE_TRIGGERS))))


def file_snapshot(path):
 # Missing optional parent is recorded only if its nearest existing ancestor is
 # protected; mkdir is restricted to explicit installer targets.
 p=Path(path)
 ancestor=p.parent
 while not ancestor.exists():
  if ancestor.is_symlink():raise Refused('missing-parent symlink')
  ancestor=ancestor.parent
 safe_chain(ancestor)
 if not p.parent.exists():return {'absent':True}
 return read_file(path)


def private_json(path,value):
 safe_chain(path.parent)
 if path.exists() or path.is_symlink():raise Refused('private evidence exists')
 raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
 temp=path.parent/('.evidence-'+secrets.token_hex(16))
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  # link gives atomic no-clobber publication; remove the private temporary name.
  os.link(temp,path,follow_symlinks=False);temp.unlink()
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:
  try:temp.unlink()
  except FileNotFoundError:pass



def remove_member_bytes(raw,gshadow=False):
 lines=raw.decode('ascii').splitlines(keepends=True);count=0;out=[]
 for line in lines:
  if line.startswith('docker:'):
   fields=line.rstrip('\n').split(':')
   if len(fields)!=4 or (not gshadow and fields[2]!='987'):raise Refused('Docker group contract')
   members=fields[3].split(',') if fields[3] else []
   if members.count('chatops')!=1:raise Refused('Docker membership baseline')
   fields[3]=','.join(x for x in members if x!='chatops');line=':'.join(fields)+'\n';count+=1
  out.append(line)
 if count!=1:raise Refused('Docker group count')
 return ''.join(out).encode('ascii')


class Host:
 def __init__(self,store,manifest):
  if os.geteuid()!=0:raise Refused('root adapter only')
  self.store=store;self.manifest=manifest;self.proofs={}
 def base(self):
  state=self.store.read()
  if not state or not state['steps']:raise Refused('baseline absent')
  return state['steps'][0]['before']
 def snapshot(self,phase):
  if phase=='backup':
   return {'files':{p:file_snapshot(p) for p in READ_TARGETS},'socket':socket_identity(),
    'runtime':{'containers':containers(),'units':units()},'contexts':long_lived_chatops_contexts()}
  if phase=='socket_cutover':return {'socket':socket_identity()}
  if phase in ('install_components','socket_persistence','remove_membership','remove_unsafe_sudo','quarantines'):
   return {'files':{p:file_snapshot(p) for p in self.paths_for(phase)}}
  return {'proof':self.proofs.get(phase)}
 def paths_for(self,phase):
  return {'install_components':(BROKER,HELPER,MYCB_UNIT,NEW_SUDO),
   'socket_persistence':(DROPIN_PATH,),
   'remove_membership':('/etc/group','/etc/gshadow'),
   'remove_unsafe_sudo':SUDO_PATHS,
   'quarantines':tuple(QUARANTINE_HASHES)+tuple('/etc/systemd/system/'+u for u in TRIGGER_SERVICES if u!='tu1nz-bot.service')}[phase]
 def preflight(self,phase,before):
  if phase=='backup':
   if pwd.getpwnam('chatops').pw_uid!=1001 or grp.getgrnam('docker').gr_gid!=987:raise Refused('account identity drift')
   for path,expected in self.manifest['baseline_files'].items():
    rec=before['files'].get(path)
    if rec is None:rec=file_snapshot(path)
    if rec.get('sha256')!=expected:raise Refused('source baseline drift: '+path)
   if before['socket']['uid']!=0 or before['socket']['gid']!=987 or before['socket']['mode']!=0o660:raise Refused('socket baseline drift')
   for p in (BROKER,HELPER,NEW_SUDO,DROPIN_PATH,'/etc/docker/daemon.json'):
    if before['files'][p]!={'absent':True}:raise Refused('unexpected preexisting installation: '+p)
   self.validate_creator()
   verify_container_continuity(self.manifest['runtime']['containers'],before['runtime']['containers'])
   verify_unit_continuity(self.manifest['runtime']['units'],before['runtime']['units'])
   for u,row in before['runtime']['units'].items():
    if row['NeedDaemonReload']!='no':raise Refused('pending foreign reload: '+u)
   self.no_running_unsafe_triggers();self.schedule_preflight()
   if not file_snapshot(ROOT/'QUARANTINE_RELEASE_NOT_AUTHORIZED').get('absent'):raise Refused('quarantine release marker exists')
   # root-only lifecycle check compares root file data with current container
   # internally. Secret values are never returned or recorded.
   ctl=Lifecycle();env,image=ctl.check();ctl.validate_runtime(ctl.current(),env,image)
   extra=extra_gid_interfaces()
   if extra['extra_interfaces']:raise Refused('preflight additional GID interface')
   from namespaces_v9 import audit_views
   self.proofs['preflight_namespaces']=audit_views(before['contexts'])
   self.proofs['backup']=True
  elif phase=='clients_before':self.no_running_unsafe_triggers()
  elif phase=='remove_membership':
   if self.proofs.get('monitoring_containers') is None:raise Refused('pre-seal monitoring absent')
  return True
 def validate_creator(self):
  raw=checked(['/usr/bin/systemctl','show','docker.socket','-p','FragmentPath','-p','DropInPaths','-p','Listen','-p','SocketUser','-p','SocketGroup','-p','SocketMode','-p','ActiveState']).decode()
  props=dict(x.split('=',1) for x in raw.splitlines())
  if props.get('FragmentPath')!='/usr/lib/systemd/system/docker.socket' or props.get('DropInPaths') or props.get('ActiveState')!='active' or props.get('Listen')!='/run/docker.sock (Stream)':raise Refused('socket creator drift')
  raw=checked(['/usr/bin/systemctl','show','docker.service','-p','ExecStart','-p','DropInPaths']).decode()
  if 'argv[]=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock ;' not in raw or 'DropInPaths=\n' not in raw:raise Refused('daemon creator drift')
 def schedule_preflight(self):
  from datetime import datetime,timezone
  values=[];now=datetime.now(timezone.utc);mono=time.monotonic_ns()
  for timer in TIMERS:
   raw=checked(['/usr/bin/systemctl','show',timer,'-p','NextElapseUSecRealtime','--value'],environment={'TZ':'UTC'}).decode().strip()
   try:due=datetime.strptime(raw,'%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc)
   except ValueError:raise Refused('timer realtime schedule unparsable')
   values.append(mono+int((due-now).total_seconds()*1e9))
  state=self.store.read()
  remaining=max(0,(state['deadline_ns']-time.monotonic_ns())/1e9)
  return schedule_window(datetime.now(timezone.utc),remaining,values,time.monotonic_ns())
 def no_running_unsafe_triggers(self):
  for u in TRIGGER_SERVICES:
   raw=checked(['/usr/bin/systemctl','show',u,'-p','ActiveState','-p','SubState']).decode()
   if 'ActiveState=inactive\n' not in raw or 'SubState=dead\n' not in raw:raise Refused('unsafe trigger executing: '+u)
 def candidate(self,path):return base64.b64decode(self.manifest['candidates'][path]['data'],validate=True) if self.manifest['candidates'][path]['data'] is not None else None
 def install_path(self,path):
  current=file_snapshot(path);candidate=self.manifest['candidates'][path]
  raw=self.candidate(path)
  if raw is not None and hashlib.sha256(raw).hexdigest()!=candidate['sha256']:raise Refused('candidate digest')
  if raw is None and current.get('absent'):return
  if raw is not None and current.get('sha256')==candidate['sha256'] and current.get('mode')==candidate['mode'] and current.get('gid')==candidate['gid']:return
  original=self.base()['files'][path]
  if not same_identity(current,original):raise Refused('candidate/original identity mismatch: '+path)
  write_exact(path,raw,current,mode=candidate['mode'],gid=candidate['gid'])
 def apply(self,phase,state):
  if phase=='backup':
   private_json(ROOT/'original.json',self.base());self.proofs[phase]=True
  elif phase=='watchdog':
   checked(['/usr/bin/systemctl','--quiet','enable','--now','tu1nz-root-only-v9-watchdog.timer'])
   raw=checked(['/usr/bin/systemctl','show','tu1nz-root-only-v9-watchdog.timer','-p','ActiveState','-p','UnitFileState']).decode()
   if 'ActiveState=active\n' not in raw or 'UnitFileState=enabled\n' not in raw:raise Refused('watchdog not armed')
   self.proofs[phase]=True
  elif phase=='install_components':
   for p in self.paths_for(phase):self.install_path(p)
  elif phase=='validate_units_sudoers':
   checked(['/usr/sbin/visudo','-c'],timeout=20)
   checked(['/usr/bin/systemd-analyze','verify','--man=no',MYCB_UNIT,str(PACKAGE/'tu1nz-root-only-v9-watchdog.service')],timeout=20)
   self.proofs[phase]=True
  elif phase=='socket_persistence':
   self.install_path(DROPIN_PATH);checked(['/usr/bin/systemctl','daemon-reload'])
  elif phase=='clients_before':self.proofs[phase]=clear_clients(self.base()['runtime'])
  elif phase=='socket_cutover':
   fixed_cutover(self.base()['socket'],lambda:private_json(ROOT/'socket-cutover-intent.json',{'before':self.base()['socket']}));self.proofs[phase]=clear_clients(self.base()['runtime'])
  elif phase=='root_docker':self.proofs[phase]=containers()
  elif phase=='fresh_chatops_denied':self.proofs[phase]=fresh_probe()
  elif phase=='old_contexts_denied':
   result=[]
   for ident in long_lived_chatops_contexts():result.append({'identity':ident,'result':negative_context_probe(ident)})
   if not result:raise Refused('no old-context coverage')
   self.proofs[phase]=result
  elif phase=='monitoring_containers':self.proofs[phase]={'runtime':protected_services_unchanged(self.base()['runtime']),'monitoring':monitoring()}
  elif phase=='remove_membership':self.remove_membership()
  elif phase=='remove_unsafe_sudo':
   for p in SUDO_PATHS:self.install_path(p)
   checked(['/usr/sbin/visudo','-c'])
  elif phase=='quarantines':self.quarantine()
  elif phase=='broker_tests':self.proofs[phase]=self.broker_tests()
  elif phase=='application_checks':self.proofs[phase]=self.application_checks()
  elif phase=='authority_graph':self.proofs[phase]=self.authority_graph()
  elif phase=='finalize':
   start=time.monotonic_ns();observations=[]
   for target in (0,30,60,91):
    while time.monotonic_ns()-start<target*1_000_000_000:time.sleep(.1)
    observations.append({'elapsed_ns':time.monotonic_ns()-start,'result':self.final_checks()})
   if observations[-1]['elapsed_ns']<90_000_000_000:raise Refused('observation too short')
   private_json(ROOT/'stability.json',{'start_ns':start,'observations':observations})
   self.wait_for_client('finalize');self.final_sudo();self.proofs[phase]=self.final_checks()
  else:raise Refused('unknown phase')
 def verify(self,phase,before,after,state):
  if phase in ('install_components','socket_persistence','remove_membership','remove_unsafe_sudo','quarantines'):
   for p in self.paths_for(phase):
    candidate=self.manifest['candidates'][p];rec=after['files'][p]
    if candidate['data'] is None:
     if rec!={'absent':True}:raise Refused('deleted target still exists')
    elif (rec.get('sha256'),rec.get('mode'),rec.get('gid'))!=(candidate['sha256'],candidate['mode'],candidate['gid']):raise Refused('candidate verification: '+p)
   if phase=='socket_persistence':self.verify_persistence()
   if phase=='remove_membership' and ('chatops' in grp.getgrnam('docker').gr_mem or 987 in os.getgrouplist('chatops',pwd.getpwnam('chatops').pw_gid)):raise Refused('NSS membership retained')
   return True
  if phase=='socket_cutover':return after['socket']=={**self.base()['socket'],'uid':0,'gid':0,'mode':0o600}
  return self.proofs.get(phase) is not None
 def verify_persistence(self):
  raw=checked(['/usr/bin/systemctl','show','docker.socket','-p','SocketUser','-p','SocketGroup','-p','SocketMode','-p','DropInPaths']).decode()
  props=dict(x.split('=',1) for x in raw.splitlines())
  if props!={'SocketUser':'root','SocketGroup':'root','SocketMode':'0600','DropInPaths':DROPIN_PATH}:raise Refused('loaded socket persistence mismatch')
 def remove_membership(self):
  libc=ctypes.CDLL(None)
  if libc.lckpwdf()!=0:raise Refused('account database lock')
  try:
   for p in ('/etc/group','/etc/gshadow'):self.install_path(p)
  finally:libc.ulckpwdf()
 def quarantine(self):
  self.no_running_unsafe_triggers()
  # Freeze only the four authorized scheduling sources. No service ExecStop,
  # compose down, container action or missed timer replay is invoked.
  checked(['/usr/bin/systemctl','stop',*TIMERS])
  for p in self.paths_for('quarantines'):self.install_path(p)
  checked(['/usr/bin/systemctl','daemon-reload'])
 def broker_tests(self):
  u=pwd.getpwnam('chatops')
  def drop():os.setgroups(os.getgrouplist('chatops',u.pw_gid));os.setgid(u.pw_gid);os.setuid(u.pw_uid)
  import subprocess
  results={}
  for op in ('status','containers','journal-counts','security-backup'):
   r=subprocess.run(['/usr/bin/sudo','-n',BROKER,op],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,preexec_fn=drop,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/')
   if r.returncode or r.stderr or len(r.stdout)>1_000_000 or json.loads(r.stdout).get('status')!='OK':raise Refused('broker positive test')
   results[op]='OK'
  for args in ([],['unknown'],['containers','--privileged'],['mychatbuddy-start','other']):
   r=subprocess.run(['/usr/bin/sudo','-n',BROKER,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,preexec_fn=drop,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/')
   if r.returncode==0:raise Refused('broker negative test')
  return results
 def application_checks(self):
  runtime=protected_services_unchanged(self.base()['runtime']);mon=monitoring()
  # These are later read-only health GETs, never bot/provider operations.
  for url in ('https://tu1nz.com','https://api.mychatbuddy.dev/mommyramona/health'):
   result=checked(['/usr/bin/curl','--noproxy','*','--fail','--silent','--show-error','--max-time','10','--output','/dev/null','--write-out','%{http_code}',url],timeout=15)
   if result!=b'200':raise Refused('health HTTP status')
  self.wait_for_client('application_checks')
  return {'runtime':runtime,'monitoring':mon,'websites':'OK','client_receipt':True}
 def authority_graph(self):
  from verification_v9 import verify
  return verify(self)
 def wait_for_client(self,phase):
  state=self.store.read()
  if state['steps'][-1]['phase']!=phase or state['status']!='INTENT':raise Refused('client receipt phase')
  state['awaiting_client']=True;self.store.write(state)
  path=ROOT/('receipt-'+phase+'.json')
  while time.monotonic_ns()<state['deadline_ns']-120_000_000_000:
   try:
    record=read_file(path)
    if record.get('absent'):time.sleep(.5);continue
    rec=json.loads(bytes_of(record))
    if rec['phase']!=phase or rec['deadline_ns']!=state['deadline_ns'] or rec['capsule_sha256']!=state['capsule_sha256']:raise Refused('client receipt binding')
    if not state['steps'][-1]['started_ns']<=rec['confirmed_monotonic_ns']<=time.monotonic_ns():raise Refused('client receipt time')
    return True
   except FileNotFoundError:pass
   if not path.exists():time.sleep(.5);continue
  raise Refused('client receipt deadline')
 def final_checks(self):
  protected_services_unchanged(self.base()['runtime']);fresh_probe();clear_clients(self.base()['runtime']);self.verify_persistence()
  return {'monitoring':monitoring(),'socket':socket_identity()}
 def restore(self,phase,before,policy):
  sealed=policy['socket']=='KEEP_ROOT_ONLY'
  if sealed:
   # Forward-complete all security closures; never label partial revocation a
   # verified SECURED_STOP. Foreign drift still refuses overwrite.
   self.remove_membership()
   for p in SUDO_PATHS:self.install_path(p)
   self.install_path(DROPIN_PATH);self.quarantine();self.final_sudo()
   checked(['/usr/sbin/visudo','-c']);self.verify_persistence()
   if socket_identity()['mode']!=0o600 or socket_identity()['gid']!=0 or socket_identity()['uid']!=0:raise Refused('sealed socket drift')
   return
  if phase=='socket_cutover':
   original=self.base()['socket'];current=socket_identity();intent=file_snapshot(ROOT/'socket-cutover-intent.json')
   if not intent.get('absent') and json.loads(bytes_of(intent))!={'before':original}:raise Refused('socket intent binding')
   rollback_postimage(original,current,not intent.get('absent'))
   if current!=original:restore_socket(current,original,False)
  if 'files' in before:
   for path,original in before['files'].items():
    if phase=='backup':continue
    current=file_snapshot(path)
    if same_content(current,original):continue
    candidate=self.manifest['candidates'][path]
    if (current.get('sha256'),current.get('uid'),current.get('mode'),current.get('gid'))!=(candidate.get('sha256'),0,candidate['mode'],candidate['gid']):raise Refused('foreign rollback target')
    write_exact(path,bytes_of(original),current,original.get('mode',0o644),original.get('gid',0),None if original.get('absent') else (original['atime_ns'],original['mtime_ns']))
   checked(['/usr/bin/systemctl','daemon-reload'])
 def verify_restore(self,phase,before,policy):
  if policy['socket']=='KEEP_ROOT_ONLY':
   sock=socket_identity()
   if any(sock[k]!=v for k,v in {'uid':0,'gid':0,'mode':0o600,'dev':self.base()['socket']['dev'],'ino':self.base()['socket']['ino']}.items()):return False
   for ph in ('install_components','socket_persistence','remove_membership','remove_unsafe_sudo','quarantines'):
    for path in self.paths_for(ph):
     cand=self.manifest['final_sudo'] if path==NEW_SUDO else self.manifest['candidates'][path]
     rec=file_snapshot(path)
     if cand['data'] is None:
      if rec!={'absent':True}:return False
     elif (rec.get('sha256'),rec.get('uid'),rec.get('gid'),rec.get('mode'))!=(cand['sha256'],0,cand['gid'],cand['mode']):return False
   self.verify_persistence()
   return 987 not in os.getgrouplist('chatops',pwd.getpwnam('chatops').pw_gid)
  if phase=='socket_cutover':return socket_identity()==self.base()['socket']
  if 'files' in before and phase!='backup':return all(same_content(file_snapshot(p),v) for p,v in before['files'].items())
  return True
 def final_sudo(self):
  current=file_snapshot(NEW_SUDO);target=self.manifest['final_sudo'];temporary=self.manifest['candidates'][NEW_SUDO]
  if (current.get('sha256'),current.get('uid'),current.get('gid'),current.get('mode'))==(target['sha256'],0,0,0o440):return
  if (current.get('sha256'),current.get('uid'),current.get('gid'),current.get('mode'))!=(temporary['sha256'],0,0,0o440):raise Refused('temporary sudo drift')
  write_exact(NEW_SUDO,base64.b64decode(target['data'],validate=True),current,0o440,0)
  rec=file_snapshot(NEW_SUDO)
  if (rec['sha256'],rec['uid'],rec['gid'],rec['mode'])!=(target['sha256'],0,0,0o440):raise Refused('final sudo verification')
  checked(['/usr/sbin/visudo','-c'])
 def final_verify(self,state):
  self.final_checks();self.authority_graph()
  return any(x['phase']=='authority_graph' and x['status']=='DONE' for x in state['steps'])
 def disable_watchdog(self):
  checked(['/usr/bin/systemctl','--quiet','disable','--now','tu1nz-root-only-v9-watchdog.timer'])
  raw=checked(['/usr/bin/systemctl','show','tu1nz-root-only-v9-watchdog.timer','-p','ActiveState','-p','UnitFileState']).decode()
  if 'ActiveState=inactive\n' not in raw or 'UnitFileState=disabled\n' not in raw:raise Refused('watchdog stop not verified')
