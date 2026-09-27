"""Fixed MyChatBuddy lifecycle contract; no free image/path/network arguments.

Installation and check are non-starting. Root-only operations run only after a
pinned installed wrapper has checked this package and its manifest.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import re
import signal
import time
from policy_v9 import Refused
from command_v9 import command

UNIT_SHA='53a2fad8675a6cfa79196d2fea64e56745403cdc4802ae93cb32682c13d71d26'
NAME='mychatbuddy-private-alpha'
IMAGE='sha256:cda7116fc1e48ce35fb537dac8e447cf60b6bbd0c98db2b82e9c96f2809f422f'
NETWORK_ID='b7fcb88ebd3ee221123e01268024d8c3955e3dfab028f81573090f013fc1b167'
ENV_PATH='/etc/tu1nz/mychatbuddy/runtime.env'
ENV_SHA='0a3c9c7c47e732412e642e8d7807e9391bd832efd089fdce39070557880b4c4b'
KEYS=('MCB_MODE MCB_OPERATION MCB_ACTIVATION_ENABLED MCB_BINDING_ENABLED MCB_DIALOG_ENABLED MCB_FIRST_START_MODE MCB_DATABASE_URL MCB_OWNER_ID MCB_OWNER_IS_ADULT MCB_LLM_ADAPTER MCB_TELEGRAM_ADAPTER MCB_MAX_INPUT_CHARS MCB_RATE_LIMIT_REQUESTS MCB_RATE_LIMIT_WINDOW_SECONDS MCB_CONVERSATION_RETENTION_DAYS MCB_DEDUPE_RETENTION_DAYS MCB_AUDIT_RETENTION_DAYS MCB_TELEGRAM_MAX_UPDATE_BYTES MCB_TELEGRAM_POLL_TIMEOUT_SECONDS MCB_OPENROUTER_MODEL MCB_OPENROUTER_PROVIDER_ROUTE MCB_OPENROUTER_MAX_INPUT_TOKENS MCB_OPENROUTER_MAX_OUTPUT_TOKENS MCB_PROVIDER_CONNECT_TIMEOUT_SECONDS MCB_PROVIDER_READ_TIMEOUT_SECONDS MCB_PROVIDER_WRITE_TIMEOUT_SECONDS MCB_PROVIDER_POOL_TIMEOUT_SECONDS MCB_PROVIDER_MAX_ATTEMPTS MCB_PROVIDER_MAX_REQUEST_COST_USD MCB_PROVIDER_FIRST_START_LIMIT_USD MCB_PROVIDER_DAILY_LIMIT_USD MCB_PROVIDER_MONTHLY_LIMIT_USD').split()
CREDENTIALS={'MCB_ENCRYPTION_KEY_FILE':'encryption-key','MCB_AUDIT_HMAC_KEY_FILE':'audit-hmac-key','MCB_INTERNAL_SIGNING_KEY_FILE':'internal-signing-key','MCB_TELEGRAM_BOT_TOKEN_FILE':'telegram-bot-token','MCB_OPENROUTER_API_KEY_FILE':'openrouter-api-key'}
PREFIX=['/usr/bin/docker','--config','/var/lib/tu1nz-codex-ops/docker','--host','unix:///run/docker.sock']
ANCHOR=None  # No new mount aliases or changed application storage contract.


def parse_action(args):
 if len(args)!=1 or args[0] not in ('check','run','stop'):raise Refused('operation denied')
 return args[0]


def parse_environment(raw,expected=ENV_SHA):
 if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=expected:raise Refused('environment hash/size')
 try:lines=raw.decode('utf8','strict').splitlines()
 except UnicodeError:raise Refused('environment encoding') from None
 result={}
 for line in lines:
  line=line.strip()
  if not line or line.startswith('#'):continue
  key,sep,value=line.partition('=')
  if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*',key) or key in result:raise Refused('environment key contract')
  if any(x in value for x in ('\x00','\r','`','$')):raise Refused('environment syntax')
  try:parts=shlex.split(value,posix=True)
  except ValueError:raise Refused('environment syntax') from None
  if len(parts)>1:raise Refused('environment multiline/unquoted spacing')
  result[key]=parts[0] if parts else ''
 # The hash fixes the entire root file; unused names never enter Docker.
 return {k:v for k,v in result.items() if k in KEYS}


def expected_mounts(anchored=False):
 if anchored:raise Refused('changed mount sources forbidden')
 root='/run/mychatbuddy/credentials'
 mounts=[('/data','/var/lib/tausendunde1nz/mychatbuddy',True)]
 mounts +=[('/run/credentials/'+name,root+'/'+name,False) for name in CREDENTIALS.values()]
 return mounts


def validate_container(c,anchored=False):
 h=c['HostConfig'];cfg=c['Config']
 if c['Image']!=IMAGE or cfg['User']!='10001:10001':raise Refused('image/user drift')
 if h['Privileged'] or h['PortBindings'] or h.get('PublishAllPorts') or not h['ReadonlyRootfs'] or h['CapDrop']!=['ALL']:raise Refused('container privilege drift')
 if h.get('PidMode') or h.get('IpcMode')=='host' or h.get('Devices') or h.get('CapAdd'):raise Refused('host authority drift')
 if h['NetworkMode']!=NAME or not h['AutoRemove'] or h['RestartPolicy']['Name']!='no':raise Refused('lifecycle/network drift')
 if set(c['NetworkSettings']['Networks'])!={NAME} or c['NetworkSettings']['Networks'][NAME]['NetworkID']!=NETWORK_ID:raise Refused('network identity drift')
 observed=sorted((m['Destination'],m['Source'],bool(m['RW'])) for m in c['Mounts'])
 if observed!=sorted(expected_mounts(anchored)) or any(m['Type']!='bind' for m in c['Mounts']):raise Refused('mount contract drift')
 if h['Memory']!=512*1024*1024 or h['NanoCpus']!=1_000_000_000 or h['PidsLimit']!=128:raise Refused('resource drift')
 if not h.get('Init') or h.get('Tmpfs')!={'/tmp':'rw,noexec,nosuid,nodev,mode=0700,uid=10001,gid=10001'}:raise Refused('init/tmpfs drift')
 if h.get('SecurityOpt')!=['no-new-privileges:true']:raise Refused('security options drift')
 return True


def run_argv():
 argv=PREFIX+['run','--rm','--name',NAME,'--pull','never','--init','--network',NAME,
  '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','128',
  '--memory','512m','--cpus','1.0','--restart','no','--stop-timeout','30']
 for dst,src,rw in expected_mounts(False):argv+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
 argv+=['--tmpfs','/tmp:rw,noexec,nosuid,nodev,mode=0700,uid=10001,gid=10001']
 for key in KEYS:argv+=['--env',key]
 for key,name in CREDENTIALS.items():argv+=['--env',key+'=/run/credentials/'+name]
 return argv+[IMAGE]


def stop_argv():return PREFIX+['stop','--timeout','30',NAME]


def inspect_argv():return PREFIX+['inspect',NAME]


def unit_candidate(original):
 if hashlib.sha256(original).hexdigest()!=UNIT_SHA:raise Refused('unit baseline drift')
 out=[];changed=0
 for line in original.decode().splitlines():
  if line=='SupplementaryGroups=docker':line='SupplementaryGroups=';changed+=1
  elif line.startswith('ExecStartPre=/usr/bin/docker image inspect '):line='ExecStartPre=!/usr/local/sbin/tu1nz-mychatbuddy-lifecycle check';changed+=1
  elif line.startswith('ExecStart=/usr/bin/docker run '):line='ExecStart=!/usr/local/sbin/tu1nz-mychatbuddy-lifecycle run';changed+=1
  elif line.startswith('ExecStop=-/usr/bin/docker stop '):line='ExecStop=!/usr/local/sbin/tu1nz-mychatbuddy-lifecycle stop';changed+=1
  out.append(line)
 if changed!=4:raise Refused('unit directive count')
 return ('\n'.join(out)+'\n').encode()


def read_root_environment():
 p=Path(ENV_PATH)
 for path in list(reversed(p.parents))+[p]:
  s=path.lstat()
  if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused('environment ownership')
  if any('posix_acl' in x for x in os.listxattr(path)):raise Refused('environment ACL')
 before=p.stat();fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  actual=os.fstat(f.fileno());raw=f.read(65537);after=os.fstat(f.fileno())
 if (before.st_dev,before.st_ino)!=(actual.st_dev,actual.st_ino) or (actual.st_size,actual.st_mtime_ns,actual.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Refused('environment drift')
 return parse_environment(raw)


def docker(argv,environment=None,timeout=10):
 if argv[:len(PREFIX)]!=PREFIX:raise Refused('daemon/config selection')
 env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/var/empty'}
 if environment:
  if set(environment)-set(KEYS):raise Refused('unexpected environment')
  env.update(environment)
 rc,out,err=command(argv,timeout=timeout,environment=env)
 if rc:
  if argv==inspect_argv() and rc==1 and out.strip()==b'[]' and err.strip() in (
    ('Error: No such object: '+NAME).encode(),('Error response from daemon: No such container: '+NAME).encode()):return None
  raise Refused('docker operation failed')
 if err:raise Refused('unexpected docker diagnostic')
 return out



class Lifecycle:
 def __init__(self,run=docker,load_env=read_root_environment,replace=None):self.command=run;self.load_env=load_env;self.replace=replace or exec_fixed
 def check(self):
  env=self.load_env()
  image=json.loads(self.command(PREFIX+['image','inspect',IMAGE]))[0]
  network=json.loads(self.command(PREFIX+['network','inspect',NAME]))[0]
  if image['Id']!=IMAGE or image['Config']['User']!='10001:10001':raise Refused('fixed image drift')
  if network['Id']!=NETWORK_ID or network['Name']!=NAME or network['Driver']!='bridge' or network['Internal'] is not False:raise Refused('fixed network drift')
  return env,image['Config']
 def current(self):
  raw=self.command(inspect_argv(),timeout=3)
  if raw is None:return None
  data=json.loads(raw)
  if len(data)!=1 or data[0]['Name']!='/'+NAME:raise Refused('container selection')
  validate_container(data[0]);return data[0]
 def stop(self):
  # No environment parse or group membership is needed to stop the existing
  # pre-reload instance. The unit executes this helper with the '!' root-credential prefix.
  c=self.current()
  if c is None:return 0
  if c['State']['Running']:self.command(stop_argv(),timeout=35)
  c=self.current()
  if c is not None and c['State']['Running']:raise Refused('container did not stop')
  return 0
 def validate_runtime(self,c,env,image,require_running=True):
  if c is None or (require_running and not c['State']['Running']):raise Refused('fixed container not running')
  if c['Config'].get('Entrypoint')!=image.get('Entrypoint') or c['Config'].get('Cmd')!=image.get('Cmd'):raise Refused('entrypoint drift')
  expected=dict(x.split('=',1) for x in image.get('Env',[]) if '=' in x)
  for key in KEYS:expected.pop(key,None)
  expected.update(env);expected.update({k:'/run/credentials/'+v for k,v in CREDENTIALS.items()})
  actual=dict(x.split('=',1) for x in c['Config'].get('Env',[]) if '=' in x)
  if actual!=expected:raise Refused('container environment drift')
  return True
 def run(self):
  env,image=self.check();c=self.current()
  if c is None:return self.replace(run_argv(),env)
  self.validate_runtime(c,env,image,require_running=False)
  if c['State']['Running']:return self.replace(PREFIX+['attach','--no-stdin',NAME],env)
  return self.replace(PREFIX+['start','--attach',NAME],env)


def exec_fixed(argv,environment):
 # Preserve Docker's original attached lifecycle, logs, signal handling and exit
 # status. No detached-run/wait race, no second container, no free Docker argv.
 allowed=(run_argv(),PREFIX+['attach','--no-stdin',NAME],PREFIX+['start','--attach',NAME])
 if argv not in allowed or set(environment)-set(KEYS):raise Refused('fixed exec contract')
 env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/var/empty'};env.update(environment)
 os.execve(PREFIX[0],argv,env)


def main(args):
 if os.geteuid()!=0:raise Refused('root lifecycle only')
 action=parse_action(args);ctl=Lifecycle()
 def interrupted(signum,frame):raise InterruptedError('lifecycle interrupted')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 if action=='check':ctl.check();return 0
 if action=='stop':return ctl.stop()
 return ctl.run()
