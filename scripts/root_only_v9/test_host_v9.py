"""Execute the actual phase adapter against a fixed, non-executing host double.

The transaction journal still uses real private files, fsync and replacement.
Every host command is intercepted. No production API or path is accessed.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import host_v9 as h
import lifecycle_v9 as life
import candidates_v9 as candidates
import sudo_candidate_v9 as sudo
import namespaces_v9
from policy_v9 import PHASES,Refused
from transaction_v9 import Store,Transaction

UNIT=b'[Unit]\nDescription=isolated fixture\n[Service]\nUser=tu1nz-mychatbuddy\nSupplementaryGroups=docker\nExecStartPre=/usr/bin/docker image inspect fixture\nExecStart=/usr/bin/docker run fixture\nExecStop=-/usr/bin/docker stop --time 30 mychatbuddy-private-alpha\n'

class World:
 def __init__(self):
  self.serial=100;self.files={};self.commands=[];self.armed=False;self.loaded=False;self.clock=1;self.receipts=[]
  self.socket={'dev':25,'ino':1268,'uid':0,'gid':987,'mode':0o660}
  for path in h.READ_TARGETS:self.put(path,('original '+path+'\n').encode())
  for p in (h.NEW_SUDO,h.BROKER,h.HELPER,h.DROPIN_PATH,'/etc/docker/daemon.json'):self.files[p]={'absent':True}
  self.put('/etc/group',b'chatops:x:1001:\ndocker:x:987:chatops\n')
  self.put('/etc/gshadow',b'chatops:!::\ndocker:!::chatops\n',0o640,42)
  self.put('/etc/sudoers',b'Defaults env_reset\n'+b'\n'.join(sudo.REMOVALS)+b'\n')
  self.put(h.MYCB_UNIT,UNIT)
  self.runtime={'containers':{},'units':{}}
 def put(self,path,data,mode=0o644,gid=0,timestamps=None):
  self.serial+=1
  self.files[str(path)]={'uid':0,'gid':gid,'mode':mode,'dev':1,'ino':self.serial,'mtime_ns':self.serial if timestamps is None else timestamps[1],'atime_ns':self.serial if timestamps is None else timestamps[0],'sha256':hashlib.sha256(data).hexdigest(),'data':base64.b64encode(data).decode(),'acl':'ABSENT','xattrs':'ABSENT'}
  return copy.deepcopy(self.files[str(path)])
 def read(self,path):return copy.deepcopy(self.files.get(str(path),{'absent':True}))
 def write(self,path,data,expected,mode=0o644,gid=0,timestamps=None):
  path=str(path)
  if self.read(path)!=expected:raise Refused('fixture write drift')
  if data is None:self.files[path]={'absent':True};return {'absent':True}
  return self.put(path,data,mode,gid,timestamps)
 def private(self,path,value):
  if str(path) in self.files:raise Refused('fixture evidence overwrite')
  self.put(path,json.dumps(value).encode(),0o600)
 def member(self):return b'docker:x:987:chatops\n' in base64.b64decode(self.files['/etc/group']['data'])
 def cutover(self,expected,on_intent=None):
  if self.socket!=expected:raise Refused('fixture socket drift')
  if on_intent:on_intent()
  self.socket.update(uid=0,gid=0,mode=0o600)
  return dict(self.socket)
 def restore_socket(self,current,original,sealed):
  if sealed or self.socket!=current:raise Refused('fixture restore drift')
  self.socket=dict(original)
 def checked(self,args,**kwargs):
  self.commands.append(tuple(args))
  if args[0]=='/usr/bin/curl':return b'200'
  if args[0] in ('/usr/sbin/visudo','/usr/bin/systemd-analyze'):return b''
  if args[0]!='/usr/bin/systemctl':raise AssertionError(('unexpected executable',args))
  if 'restart' in args or 'kill' in args:raise AssertionError('forbidden service operation')
  if 'enable' in args:self.armed=True;return b''
  if 'disable' in args:self.armed=False;return b''
  if 'daemon-reload' in args:self.loaded=not self.files[h.DROPIN_PATH].get('absent');return b''
  if 'stop' in args:
   if args[2:]!=list(h.TIMERS):raise AssertionError(('unapproved stop',args))
   return b''
  if 'show' in args:
   unit=args[2]
   if unit=='docker.socket':
    if '-p' in args and 'Listen' in args:return b'FragmentPath=/usr/lib/systemd/system/docker.socket\nDropInPaths=\nListen=/run/docker.sock (Stream)\nActiveState=active\n'
    return ('SocketUser=root\nSocketGroup='+('root' if self.loaded else 'docker')+'\nSocketMode='+('0600' if self.loaded else '0660')+'\nDropInPaths='+(h.DROPIN_PATH if self.loaded else '')+'\n').encode()
   if unit=='docker.service':return b'ExecStart={ argv[]=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock ; }\nDropInPaths=\n'
   if unit=='tu1nz-root-only-v9-watchdog.timer':return ('ActiveState='+('active' if self.armed else 'inactive')+'\nUnitFileState='+('enabled' if self.armed else 'disabled')+'\n').encode()
   if unit in h.TRIGGER_SERVICES:return b'ActiveState=inactive\nSubState=dead\n'
  raise AssertionError(('unexpected command',args))
 def subprocess(self,args,**kwargs):
  self.commands.append(tuple(args))
  if len(args)==4 and args[:3]==['/usr/bin/sudo','-n',h.BROKER] and args[3] in ('status','containers','journal-counts','security-backup'):
   return subprocess.CompletedProcess(args,0,b'{"status":"OK"}',b'')
  return subprocess.CompletedProcess(args,1,b'',b'denied')
 def sleep(self,seconds):self.clock+=int(seconds*1e9)

class ActualHostTests(unittest.TestCase):
 def fixture(self):
  return Fixture(self)
 def test_final_graph_revalidated(self):
  with self.fixture() as f:
   calls=[]
   f.host.authority_graph=lambda:calls.append('verified') or {'verified':True}
   for phase in PHASES:f.tx.step(phase)
   f.tx.finish();self.assertEqual(len(calls),2)
 def test_actual_adapter_success(self):
  with self.fixture() as f:
   for phase in PHASES:f.tx.step(phase)
   f.tx.finish();self.assertEqual(f.store.read()['status'],'COMPLETE');self.assertFalse(f.world.armed)
   self.assertEqual(f.world.socket['mode'],0o600);self.assertFalse(f.world.member())
   self.assertEqual(f.world.receipts,['application_checks','finalize'])
   self.assertGreaterEqual(f.world.clock,91_000_000_000)
 def test_actual_adapter_failure_each_phase(self):
  for phase in PHASES:
   for when in ('before','after'):
    with self.subTest(phase=phase,when=when),self.fixture() as f:
     real=f.host.apply
     def injected(p,state):
      if p==phase and when=='before':raise Refused('injected')
      real(p,state)
      if p==phase and when=='after':raise Refused('injected')
     f.host.apply=injected
     with self.assertRaises(Refused):
      for p in PHASES:f.tx.step(p)
     state=f.store.read();sealed=PHASES.index(phase)>=PHASES.index('remove_membership')
     self.assertEqual(state['status'],'SECURED_STOP' if sealed else 'ROLLED_BACK')
     if sealed:
      self.assertFalse(f.world.member());self.assertEqual(f.world.socket['mode'],0o600)
      for p in f.host.paths_for('quarantines'):self.assertEqual(f.world.files[p]['sha256'],f.host.manifest['candidates'][p]['sha256'])
     else:
      self.assertEqual(f.world.socket,f.original_socket)
      for p in h.READ_TARGETS:self.assertTrue(h.same_content(f.original_files[p],f.world.read(p)),p)
 def test_preflight_failure_does_not_mutate(self):
  with self.fixture() as f:
   f.host.manifest['baseline_files'][h.MYCB_UNIT]='bad'
   with self.assertRaises(Refused):f.tx.step('backup')
   f.tx.rollback();self.assertEqual(f.store.read()['status'],'ROLLED_BACK');self.assertEqual(f.world.files,f.original_files)
 def test_no_application_lifecycle_command(self):
  with self.fixture() as f:
   for phase in PHASES:f.tx.step(phase)
   for cmd in f.world.commands:
    self.assertNotIn('restart',cmd)
    if cmd[0]=='/usr/bin/systemctl' and 'stop' in cmd:self.assertEqual(cmd[2:],h.TIMERS)
 def test_foreign_file_refused(self):
  with self.fixture() as f:
   for phase in ('backup','watchdog'):f.tx.step(phase)
   f.world.put(h.MYCB_UNIT,b'foreign root unit')
   with self.assertRaises(Refused):f.tx.step('install_components')
   self.assertEqual(base64.b64decode(f.world.files[h.MYCB_UNIT]['data']),b'foreign root unit')
   # Foreign change predates this phase snapshot: preserve it, undo only our writes.
   self.assertEqual(f.store.read()['status'],'ROLLED_BACK')

class Fixture:
 def __init__(self,test):self.test=test
 def __enter__(self):
  self.temp=tempfile.TemporaryDirectory();os.chmod(self.temp.name,0o700)
  self.store=Store(self.temp.name,fixture=True);self.world=World();w=self.world
  self.original_files=copy.deepcopy(w.files);self.original_socket=dict(w.socket)
  hashes={p:w.files[p]['sha256'] for p in h.QUARANTINE_HASHES}
  sudo_hashes={p:w.files[p]['sha256'] for p in sudo.BASELINES}
  self.patches=[patch.dict(h.QUARANTINE_HASHES,hashes,clear=True),patch.dict(sudo.BASELINES,sudo_hashes,clear=True),patch.object(life,'UNIT_SHA',hashlib.sha256(UNIT).hexdigest()),
   patch.object(h,'file_snapshot',w.read),patch.object(h,'read_file',w.read),patch.object(h,'write_exact',w.write),patch.object(h,'private_json',w.private),
   patch.object(h,'socket_identity',lambda:dict(w.socket)),patch.object(h,'fixed_cutover',w.cutover),patch.object(h,'restore_socket',w.restore_socket),
   patch.object(h,'checked',w.checked),patch.object(subprocess,'run',w.subprocess),
   patch.object(h,'containers',lambda:{}),patch.object(h,'units',lambda:{}),patch.object(h,'long_lived_chatops_contexts',lambda:[{'fixture':True}]),
   patch.object(h,'clear_clients',lambda baseline:{'verified':True}),patch.object(h,'fresh_probe',lambda:True),patch.object(h,'negative_context_probe',lambda i:'EACCES'),
   patch.object(h,'monitoring',lambda:{'cadvisor':'up','node-exporter':'up'}),patch.object(h,'protected_services_unchanged',lambda b:b),
   patch.object(h,'extra_gid_interfaces',lambda:{'extra_interfaces':[]}),patch.object(namespaces_v9,'audit_views',lambda c:{'verified':True}),
   patch.object(h.pwd,'getpwnam',lambda n:types.SimpleNamespace(pw_uid=1001,pw_gid=1001)),
   patch.object(h.grp,'getgrnam',lambda n:types.SimpleNamespace(gr_gid=987,gr_mem=['chatops'] if w.member() else [])),
   patch.object(os,'getgrouplist',lambda n,g:[1001,987] if w.member() else [1001]),
   patch.object(h.ctypes,'CDLL',lambda n:types.SimpleNamespace(lckpwdf=lambda:0,ulckpwdf=lambda:0)),
   patch.object(h.time,'monotonic_ns',lambda:w.clock),patch.object(h.time,'sleep',w.sleep),
   patch.object(h,'Lifecycle',lambda:types.SimpleNamespace(check=lambda:({},{}),current=lambda:{},validate_runtime=lambda *a:True))]
  for p in self.patches:p.start()
  compiled=candidates.compile_candidates(w.files,b'fixed broker fixture',b'fixed helper fixture',b'fixed sudo fixture')
  self.host=object.__new__(h.Host);self.host.store=self.store;self.host.proofs={}
  self.host.manifest={'baseline_files':{**hashes,**sudo_hashes,h.MYCB_UNIT:hashlib.sha256(UNIT).hexdigest()},'runtime':w.runtime,'candidates':compiled,'final_sudo':candidates.record(b'final fixed sudo fixture',0o440)}
  self.host.schedule_preflight=lambda:True
  self.host.wait_for_client=lambda phase:w.receipts.append(phase) or True
  self.host.authority_graph=lambda:{'verified':True,'fixture_only':True}
  self.tx=Transaction(self.store,self.host,lambda:w.clock);self.tx.begin('fixture-boot',capsule_sha256='a'*64)
  return self
 def __exit__(self,*args):
  for p in reversed(self.patches):p.stop()
  self.store.close();self.temp.cleanup()

if __name__=='__main__':unittest.main()
