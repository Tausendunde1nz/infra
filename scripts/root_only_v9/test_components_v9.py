import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import command_v9 as command
import lifecycle_v9 as life
import files_v9 as files
import probes_v9 as probes
from policy_v9 import Refused


def container():
 return {'Id':'a'*64,'Name':'/'+life.NAME,'Image':life.IMAGE,
 'Config':{'User':'10001:10001','Entrypoint':None,'Cmd':['app'],'Env':[k+'=/run/credentials/'+v for k,v in life.CREDENTIALS.items()]},
 'State':{'Running':True},
 'HostConfig':{'Privileged':False,'PortBindings':{},'ReadonlyRootfs':True,'CapDrop':['ALL'],
 'NetworkMode':life.NAME,'AutoRemove':True,'RestartPolicy':{'Name':'no'},'Memory':512*1024*1024,
 'NanoCpus':1000000000,'PidsLimit':128,'Init':True,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,mode=0700,uid=10001,gid=10001'},'SecurityOpt':['no-new-privileges:true']},
 'NetworkSettings':{'Networks':{life.NAME:{'NetworkID':life.NETWORK_ID}}},
 'Mounts':[{'Type':'bind','Destination':d,'Source':s,'RW':rw} for d,s,rw in life.expected_mounts()]}

class FakeDocker:
 def __init__(self,c=None):self.c=c;self.calls=[];self.exit=b'0';self.drift=False
 def __call__(self,argv,**kw):
  self.calls.append((argv,kw))
  if argv==life.PREFIX+['image','inspect',life.IMAGE]:return json.dumps([{'Id':life.IMAGE,'Config':{'User':'10001:10001','Cmd':['app']}}]).encode()
  if argv==life.PREFIX+['network','inspect',life.NAME]:return json.dumps([{'Id':life.NETWORK_ID,'Name':life.NAME,'Driver':'bridge','Internal':False}]).encode()
  if argv==life.inspect_argv():return None if self.c is None else json.dumps([self.c]).encode()
  if argv==life.run_argv():
   self.c=container()
   if self.drift:self.c['Config']['Cmd']=['unexpected']
   return self.c['Id'].encode()
  if argv==life.stop_argv() or argv==life.PREFIX+['stop','--time','30','a'*64]:self.c=None;return b''
  if argv==life.PREFIX+['wait',life.NAME]:return self.exit
  raise AssertionError(argv)

class LifecycleTests(unittest.TestCase):
 def test_exact_action(self):
  for args in ([],['stop','x'],['run','--privileged'],['../run'],['check;id']):
   with self.subTest(args=args),self.assertRaises(Refused):life.parse_action(args)
 def test_baseline_contract(self):self.assertTrue(life.validate_container(container()))
 def test_contract_rejects_each_drift(self):
  for obj,key,value in [('Config','User','0'),('HostConfig','Privileged',True),('HostConfig','Init',False),('HostConfig','PortBindings',{'80/tcp':[{}]}),('HostConfig','Memory',0),('HostConfig','NetworkMode','host'),('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','Tmpfs',{}),('HostConfig','Devices',[{}])]:
   c=container();c[obj][key]=value
   with self.subTest(key=key),self.assertRaises(Refused):life.validate_container(c)
 def test_mount_change_refused(self):
  c=container();c['Mounts'][0]['Source']='/etc'
  with self.assertRaises(Refused):life.validate_container(c)
 def test_network_change_refused(self):
  c=container();c['NetworkSettings']['Networks'][life.NAME]['NetworkID']='foreign'
  with self.assertRaises(Refused):life.validate_container(c)
 def test_fixed_run(self):
  a=life.run_argv();self.assertEqual(a[-1],life.IMAGE);self.assertIn('--pull',a);self.assertNotIn('-p',a);self.assertNotIn('--privileged',a)
 def test_stop_existing_instance_needs_no_environment(self):
  f=FakeDocker(container());ctl=life.Lifecycle(f,lambda:(_ for _ in ()).throw(AssertionError('env must not be loaded')))
  self.assertEqual(ctl.stop(),0);self.assertIsNone(f.c);self.assertEqual(ctl.stop(),0)
 def test_check_never_runs(self):
  f=FakeDocker(container());life.Lifecycle(f,lambda:{}).check();self.assertEqual(len(f.calls),2)
 def test_existing_run_does_not_recreate(self):
  f=FakeDocker(container());calls=[]
  self.assertEqual(life.Lifecycle(f,lambda:{},lambda a,e:calls.append(a) or 0).run(),0)
  self.assertEqual(calls,[life.PREFIX+['attach','--no-stdin',life.NAME]])
  self.assertNotIn(life.run_argv(),[a for a,k in f.calls])
 def test_new_run_preserves_attached_lifecycle(self):
  f=FakeDocker();calls=[]
  self.assertEqual(life.Lifecycle(f,lambda:{},lambda a,e:calls.append(a) or 0).run(),0)
  self.assertEqual(calls,[life.run_argv()]);self.assertNotIn('--detach',calls[0])
 def test_stopped_fixed_container_start(self):
  c=container();c['State']['Running']=False;f=FakeDocker(c);calls=[]
  life.Lifecycle(f,lambda:{},lambda a,e:calls.append(a) or 0).run()
  self.assertEqual(calls,[life.PREFIX+['start','--attach',life.NAME]])
 def test_existing_drift_does_not_stop_foreign_instance(self):
  c=container();c['Config']['Cmd']=['foreign'];f=FakeDocker(c)
  with self.assertRaises(Refused):life.Lifecycle(f,lambda:{},lambda a,e:(_ for _ in ()).throw(AssertionError('no exec'))).run()
  self.assertIs(f.c,c)
 def test_exec_rejects_free_docker_argv(self):
  with self.assertRaises(Refused):life.exec_fixed(life.PREFIX+['run','alpine'],{})
 def test_env_hash(self):
  with self.assertRaises(Refused):life.parse_environment(b'MCB_MODE=x')
 def test_env_whitelist_and_absent_keys(self):
  raw=b'MCB_MODE=private\nUNUSED_KEY=not-propagated\n'
  self.assertEqual(life.parse_environment(raw,hashlib.sha256(raw).hexdigest()),{'MCB_MODE':'private'})
 def test_env_duplicate_and_injection(self):
  for raw in (b'MCB_MODE=x\nMCB_MODE=y\n',b'MCB_MODE=$(id)',b'MCB_MODE=`id`',b'bad key=x',b'MCB_MODE=a b'):
   with self.subTest(raw=raw),self.assertRaises(Refused):life.parse_environment(raw,hashlib.sha256(raw).hexdigest())
 def test_unit_rejects_unbound_original(self):
  with self.assertRaises(Refused):life.unit_candidate(b'[Service]\n')
 def test_changed_mount_alias_rejected(self):
  with self.assertRaises(Refused):life.expected_mounts(True)

class FileTests(unittest.TestCase):
 def test_atime_is_not_drift(self):self.assertTrue(files.same_identity({'ino':1,'atime_ns':2},{'ino':1,'atime_ns':3}))
 def test_inode_is_drift(self):self.assertFalse(files.same_identity({'ino':1},{'ino':2}))
 def test_content_must_match(self):self.assertFalse(files.same_content({'sha256':'a'},{'sha256':'b'}))
 def test_exact_allowlist(self):
  self.assertTrue(files.authorized('/etc/sudoers'))
  for p in ('/etc/passwd','/etc/../etc/sudoers','/tmp/sudoers','/usr/local/libexec/tu1nz-root-only-v9/foreign.py'):
   self.assertFalse(files.authorized(p))
 def test_bad_backup(self):
  with self.assertRaises(Refused):files.bytes_of({'data':'YWJj','sha256':'wrong'})

class CommandTests(unittest.TestCase):
 def test_output(self):self.assertEqual(command.checked([sys.executable,'-I','-S','-c','print(42)']),b'42\n')
 def test_nonzero(self):
  with self.assertRaises(Refused):command.checked([sys.executable,'-I','-S','-c','raise SystemExit(2)'])
 def test_stderr(self):
  with self.assertRaises(Refused):command.checked([sys.executable,'-I','-S','-c','import sys;sys.stderr.write("SECRET_SENTINEL")'])
 def test_timeout(self):
  with self.assertRaises(Refused):command.checked([sys.executable,'-I','-S','-c','import time;time.sleep(4)'],timeout=.1)
 def test_limit(self):
  with self.assertRaises(Refused):command.checked([sys.executable,'-I','-S','-c','print("x"*100000)'],limit=128)
 def test_no_relative_program(self):
  with self.assertRaises(Refused):command.command(['python3','-c','pass'])

class ACLTests(unittest.TestCase):
 def test_dac_old_gid(self):
  s=types.SimpleNamespace(st_uid=0,st_gid=987,st_mode=0o100660)
  self.assertEqual(probes.access_bits(s,b'',1001,{987}),6)
  s.st_gid=0;s.st_mode=0o100600
  self.assertEqual(probes.access_bits(s,b'',1001,{987}),0)
 def test_named_group_mask(self):
  s=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o100640)
  a=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*x) for x in [(1,6,0xffffffff),(4,0,0xffffffff),(8,6,987),(16,4,0xffffffff),(32,0,0xffffffff)])
  self.assertEqual(probes.access_bits(s,a,1001,{987}),4)
 def test_invalid_acl(self):
  s=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o600)
  with self.assertRaises(Refused):probes.access_bits(s,b'bad',1001,{987})

if __name__=='__main__':unittest.main()
