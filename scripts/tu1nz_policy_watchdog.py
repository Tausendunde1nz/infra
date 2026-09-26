#!/usr/bin/env python3
"""Mac-only public-API transaction. Credentials in Keychain; bearer tokens in RAM."""
import socket
import argparse, datetime, getpass, hashlib, json, os, pathlib, resource, signal, stat, subprocess, sys, time, urllib.request, urllib.error, urllib.parse, uuid
from tu1nz_keychain import Keychain
BASE='https://api.tailscale.com/api/v2'
ACL='/tailnet/-/acl'
SCOPES={'policy_file','devices:core:read','devices:posture_attributes'}
REQUIRED={'mac_ipv4','chatops_ipv4_22','chatops_ipv4_2222','chatops_ipv6_22','ipv6_2222_closed','root_denied','nobody_denied','daemon_denied','iphone_exit_node','iphone_internet_dns','websites_dns','node_cadvisor','fail2ban_2222','backups_docs','public_ipv4_ipv6_blocked','containers_unchanged','listeners_firewalls_unchanged','tailnet_negative_tests'}
class SafeError(Exception):pass
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(b):return json.dumps(json.loads(b),sort_keys=True,separators=(',',':')).encode()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def protect():
 os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def write_new(path,data):
 if not isinstance(data,bytes):data=json.dumps(data,indent=2).encode()+b'\n'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def read_private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077:raise SafeError('unsafe file permissions')
  return f.read()
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise SafeError('API redirect refused')
class API:
 def __init__(self,credentials=None,sleep=time.sleep):
  self.credentials=credentials or Keychain().get();self.token=None;self.until=0;self.sleep=sleep
  self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def wire(self,path,method='GET',data=None,headers=None):
  if path not in [ACL,ACL+'/validate','/oauth/token','/tailnet/-/devices']:raise SafeError('endpoint outside scope')
  for attempt in range(4):
   try:
    req=urllib.request.Request(BASE+path,data=data,headers=headers or {},method=method)
    with self.opener.open(req,timeout=12) as r:return r.read(8000000),dict(r.headers),r.status
   except urllib.error.HTTPError as e:
    code=e.code;e.close()
    if code not in [429,500,502,503,504] or attempt==3:raise SafeError('API HTTP '+str(code)) from None
   except (urllib.error.URLError,socket.timeout,TimeoutError,OSError):
    if attempt==3:raise SafeError('API network retry budget exhausted') from None
   self.sleep(2**attempt)
 def auth(self):
  if self.token and time.monotonic()<self.until:return
  body=urllib.parse.urlencode({'grant_type':'client_credentials','client_id':self.credentials['id'],'client_secret':self.credentials['secret'],'scope':' '.join(sorted(SCOPES))}).encode()
  raw,_,_=self.wire('/oauth/token','POST',body,{'Content-Type':'application/x-www-form-urlencoded'})
  d=json.loads(raw)
  if d.get('token_type','').lower()!='bearer' or not d.get('access_token'):raise SafeError('invalid OAuth response')
  if d.get('scope') and not set(d['scope'].split())<=SCOPES|{'policy_file:read','devices:posture_attributes:read'}:raise SafeError('unexpected token scope')
  self.token=d['access_token'];self.until=time.monotonic()+min(int(d['expires_in']),3600)-60
 def call(self,path,method='GET',data=None,accept='application/hujson',etag=None):
  self.auth();headers={'Authorization':'Bearer '+self.token,'Accept':accept,'Content-Type':'application/hujson'}
  if etag:headers['If-Match']=etag
  return self.wire(path,method,data,headers)
 def snapshot(self):
  for _ in range(3):
   raw,h,_=self.call(ACL);parsed,j,_=self.call(ACL,accept='application/json')
   etag=h.get('ETag') or h.get('Etag');jtag=j.get('ETag') or j.get('Etag')
   if etag and etag==jtag:return {'raw':raw,'json':canonical(parsed),'etag':etag}
  raise SafeError('policy changed during snapshot or ETag missing')
 def validate(self,raw):
  body,_,_=self.call(ACL+'/validate','POST',raw,accept='application/json')
  if body.strip() and json.loads(body)!={}:raise SafeError('policy validation/test/warning failed')
 def set(self,raw,etag):
  if not etag:raise SafeError('missing concurrency guard')
  self.call(ACL,'POST',raw,etag=etag)
def same(a,b):return a['raw']==b['raw'] or a['json']==b['json']
def restore(api,original,candidate_semantic,force=False):
 api.validate(original['raw']);current=api.snapshot()
 if current['json'] not in [original['json'],candidate_semantic]:raise SafeError('concurrent foreign policy; refusing overwrite')
 if force or not same(current,original):
  try:api.set(original['raw'],current['etag'])
  except SafeError:
   # POST may have succeeded before its response was lost; verify, never assume.
   current=api.snapshot()
   if not same(current,original):raise
 result=api.snapshot();api.validate(result['raw'])
 if not same(result,original):raise SafeError('rollback readback mismatch')
 return {'verified':True,'exact_bytes':result['raw']==original['raw'],'original_sha256':sha(original['raw']),'readback_sha256':sha(result['raw']),'semantic_equal':result['json']==original['json']}
def valid_completion(marker,manifest,report,current,clock):
 required=REQUIRED|({'independent_ssh_logins_no_check'} if manifest['stage']=='accept' else set())
 return (marker.get('transaction')==manifest['transaction'] and marker.get('candidate_sha256')==manifest['candidate_sha256'] and marker.get('report_sha256')==sha(report) and current['json']==bytes.fromhex(manifest['candidate_semantic_hex']) and set(json.loads(report).get('checks',{}))==required and all(v is True for v in json.loads(report)['checks'].values()) and manifest['started_epoch']<=json.loads(report).get('completed_epoch',0)<=clock and clock<manifest['deadline_epoch'])
def run_transaction(directory,candidate_path,seconds,stage,api=None):
 protect();directory=pathlib.Path(directory)
 if stage=='selftest':
  if not 5<=seconds<=120:raise SafeError('invalid selftest interval')
 elif not 300<=seconds<=2700:raise SafeError('invalid test interval')
 directory.mkdir(mode=0o700);api=api or API();awake=None;original=None;armed=False
 rollback_requested=False
 def interrupted(*_):
  nonlocal rollback_requested
  rollback_requested=True
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGHUP,signal.SIG_IGN)
 try:
  original=api.snapshot();api.validate(original['raw'])
  candidate=original['raw'] if stage=='selftest' else read_private(pathlib.Path(candidate_path))
  candidate_sem=original['json'] if stage=='selftest' else canonical(candidate)
  api.validate(candidate)
  write_new(directory/'original.hujson',original['raw']);write_new(directory/'original.json',original['json']);write_new(directory/'candidate.hujson',candidate)
  started=time.time();manifest={'transaction':str(uuid.uuid4()),'stage':stage,'utc':now(),'started_epoch':started,'deadline_epoch':started+seconds,'original_sha256':sha(original['raw']),'candidate_sha256':sha(candidate),'candidate_semantic_hex':candidate_sem.hex(),'original_etag':original['etag']}
  write_new(directory/'manifest.json',manifest)
  awake=subprocess.Popen(['/usr/bin/caffeinate','-is','-w',str(os.getpid())],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
  time.sleep(.1)
  if awake.poll() is not None:raise SafeError('sleep inhibitor failed')
  # In-process watchdog is already running independently of Codex and server.
  armed=True;write_new(directory/'ARMED.json',{'utc':now(),'pid':os.getpid(),'transaction':manifest['transaction']})
  if stage!='selftest':
   current=api.snapshot()
   if not same(current,original):raise SafeError('policy drift before activation')
   api.set(candidate,current['etag'])
   if api.snapshot()['json']!=candidate_sem:raise SafeError('candidate readback mismatch')
   write_new(directory/'ACTIVATED.json',{'utc':now(),'sha256':sha(candidate)})
  deadline=time.monotonic()+max(0,manifest['deadline_epoch']-time.time())
  while not rollback_requested and time.monotonic()<deadline:
   if (directory/'ROLLBACK_NOW').exists():break
   if stage!='selftest' and (directory/'COMPLETE.json').exists():
    try:
     marker=json.loads(read_private(directory/'COMPLETE.json'));report=read_private(directory/'test-report.json')
     if valid_completion(marker,manifest,report,api.snapshot(),time.time()):
      write_new(directory/'SUCCESS.json',{'utc':now(),'transaction':manifest['transaction']});armed=False;return
    except (SafeError,ValueError,OSError):pass
   time.sleep(1)
  result=restore(api,original,candidate_sem,force=stage=='selftest')
  result['utc']=now();write_new(directory/'ROLLED_BACK.json',result);armed=False
 except Exception as e:
  # Never print exception contents: server responses can contain sensitive data.
  if armed and original is not None:
   try:write_new(directory/'ROLLED_BACK.json',dict(restore(api,original,candidate_sem),utc=now()));armed=False
   except Exception:write_new(directory/'ROLLBACK_FAILED.json',{'utc':now(),'manual_recovery_required':True})
  write_new(directory/'FAILED.json',{'utc':now(),'kind':type(e).__name__,'rollback_verified':not armed and original is not None and (directory/'ROLLED_BACK.json').exists()})
 finally:
  if awake is not None:
   awake.terminate();awake.wait(timeout=5)
  api.token=None;api.credentials=None
def enroll():
 protect()
 if not sys.stdin.isatty():raise SafeError('hidden interactive terminal required')
 # Abort rather than use getpass fallback which might echo input.
 import warnings
 with warnings.catch_warnings():
  warnings.simplefilter('error',getpass.GetPassWarning)
  cid=getpass.getpass('OAuth-Client-ID (verdeckt): ');secret=getpass.getpass('OAuth-Secret (verdeckt): ')
 if not cid.strip() or not secret.strip():raise SafeError('empty credential')
 value={'id':cid.strip(),'secret':secret.strip()};k=Keychain();k.put(value)
 if k.get()!=value:raise SafeError('keychain roundtrip failed')
 print('KEYCHAIN_READY — keine Policy geändert.',flush=True)
def main():
 p=argparse.ArgumentParser();sub=p.add_subparsers(dest='mode',required=True)
 sub.add_parser('enroll');sub.add_parser('cleanup')
 s=sub.add_parser('run');s.add_argument('--directory',required=True);s.add_argument('--candidate');s.add_argument('--seconds',type=int,required=True);s.add_argument('--stage',choices=['selftest','phase5','accept'],required=True)
 a=p.parse_args();protect()
 if a.mode=='enroll':enroll()
 elif a.mode=='cleanup':Keychain().delete();print('KEYCHAIN_REMOVED')
 else:run_transaction(a.directory,a.candidate,a.seconds,a.stage)
if __name__=='__main__':
 try:main()
 except Exception:print('STOP — Vorbedingung fehlgeschlagen; keine Geheimnisse ausgegeben.',file=sys.stderr);sys.exit(1)
