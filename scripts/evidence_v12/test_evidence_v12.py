import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import collector_v12 as c
import bootstrap_v12 as b

TERMS=[('IP','172.25.0.2'),('MAC','82:fb:9a:73:0e:36'),('Hostport','8081'),('Containerport','8080'),('Servicename','telegram_bot_mommyramona'),('Alias','mommy')]
IDENT={'networks':{'a':{'IPAddress':'172.25.0.2','GlobalIPv6Address':''}}}

class BootstrapTests(unittest.TestCase):
 def setUp(self):
  if not hasattr(os,'listxattr'):
   mock=patch.object(os,'listxattr',return_value=[],create=True);mock.start();self.addCleanup(mock.stop)
  self.t=tempfile.TemporaryDirectory();self.p=Path(self.t.name);self.stage=self.p/'staging';self.stage.mkdir(mode=0o700)
  self.src=self.p/'source';self.src.write_bytes(b'print("fixture")\n');self.hash=hashlib.sha256(self.src.read_bytes()).hexdigest()
 def tearDown(self):self.t.cleanup()
 def copy(self):return b.copy_verified(self.src,self.stage,self.hash,os.getuid())
 def test_prepare_copy_failure_manifest(self):
  with self.assertRaises(b.Refused):b.prepare_copy(self.src,self.p,'0'*64,os.getuid())
  self.assertEqual(json.loads((self.p/'bootstrap-aborted.json').read_text())['status'],'ABORTED_BEFORE_EXECUTION')
  self.assertFalse((self.p/'bootstrap-complete.json').exists())
 def test_prepare_copy_success_manifest(self):
  b.prepare_copy(self.src,self.p,self.hash,os.getuid())
  self.assertEqual(json.loads((self.p/'bootstrap-complete.json').read_text())['sha256'],self.hash)
 def test_copy_verified_restrictive(self):
  p=Path(self.copy());self.assertEqual(p.read_bytes(),self.src.read_bytes());self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
 def test_source_change_after_copy_no_effect(self):
  p=Path(self.copy());self.src.write_bytes(b'hostile');self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),self.hash)
 def test_wrong_hash_no_execution(self):
  self.hash='0'*64
  with self.assertRaises(b.Refused):self.copy()
 def test_symlink_source(self):
  link=self.p/'link';link.symlink_to(self.src);self.src=link
  with self.assertRaises(OSError):self.copy()
 def test_symlink_stage(self):
  link=self.p/'link';link.symlink_to(self.stage);self.stage=link
  with self.assertRaises(OSError):self.copy()
 def test_foreign_owner(self):
  with self.assertRaises(b.Refused):b.copy_verified(self.src,self.stage,self.hash,os.getuid()+50000)
 def test_group_write_stage(self):
  self.stage.chmod(0o770)
  with self.assertRaises(b.Refused):self.copy()
 def test_existing_stage_file(self):
  (self.stage/'collector.py').write_bytes(b'foreign')
  with self.assertRaises(FileExistsError):self.copy()
  self.assertEqual((self.stage/'collector.py').read_bytes(),b'foreign')
 def test_hardlink_source(self):
  os.link(self.src,self.p/'other')
  with self.assertRaises(b.Refused):self.copy()
 def test_stage_acl(self):
  with patch.object(b.os,'listxattr',return_value=['system.posix_acl_access']):
   with self.assertRaises(b.Refused):self.copy()
 def test_source_toctou(self):
  original=b.os.fstat;count=[0]
  def fstat(fd):
   count[0]+=1
   # stage=1, source type=2, pre-read=3; mutate before post-read 4.
   if count[0]==4:self.src.write_bytes(b'changed bytes longer than fixture')
   return original(fd)
  with patch.object(b.os,'fstat',side_effect=fstat):
   with self.assertRaises(b.Refused):self.copy()
 def test_bad_hash_shape(self):
  self.hash='../../bad'
  with self.assertRaises(b.Refused):self.copy()
 def test_nonroot_entry_refused(self):
  with patch.object(b.os,'geteuid',return_value=1001):
   with self.assertRaises(b.Refused):b.main()

class DBTests(unittest.TestCase):
 def fixture(self,wal=False):
  t=tempfile.TemporaryDirectory();p=Path(t.name)/'db';db=sqlite3.connect(p)
  if wal:db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
  db.execute('CREATE TABLE workflow_entity(id TEXT,active INTEGER,nodes TEXT)');db.commit()
  nodes=[{'name':'SECRET_NAME','credentials':{'token':'DO_NOT_LEAK'},'parameters':{'url':'http://172.25.0.2:8080/private?token=DO_NOT_LEAK','port':8081,'alias':'mommy'}}]
  db.execute('INSERT INTO workflow_entity VALUES (?,?,?)',('wf123',1,json.dumps(nodes)));db.commit()
  return t,p,db
 def test_no_wal_no_secret(self):
  t,p,db=self.fixture()
  try:
   result=c.scan_database(c.materialize(p.read_bytes(),b''),TERMS);s=json.dumps(result)
   self.assertNotIn('DO_NOT_LEAK',s);self.assertNotIn('SECRET_NAME',s);self.assertNotIn('/private',s)
   self.assertEqual(result['matches'][0]['record_id'],'wf123');self.assertEqual(result['workflow_count'],1)
  finally:db.close();t.cleanup()
 def test_real_committed_wal_memory_only(self):
  t,p,db=self.fixture(True)
  try:
   raw=p.read_bytes();wal=Path(str(p)+'-wal').read_bytes();before=(hashlib.sha256(raw).hexdigest(),hashlib.sha256(wal).hexdigest())
   result=c.scan_database(c.materialize(raw,wal),TERMS);self.assertEqual(result['workflow_count'],1)
   self.assertEqual(before,(hashlib.sha256(p.read_bytes()).hexdigest(),hashlib.sha256(Path(str(p)+'-wal').read_bytes()).hexdigest()))
  finally:db.close();t.cleanup()
 def test_wal_checksum_corruption(self):
  t,p,db=self.fixture(True)
  try:
   wal=bytearray(Path(str(p)+'-wal').read_bytes());wal[-1]^=1
   with self.assertRaises(c.Refused):c.materialize(p.read_bytes(),bytes(wal))
  finally:db.close();t.cleanup()
 def test_partial_wal_refused(self):
  t,p,db=self.fixture(True)
  try:
   with self.assertRaises(c.Refused):c.materialize(p.read_bytes(),Path(str(p)+'-wal').read_bytes()[:-1])
  finally:db.close();t.cleanup()
 def test_invalid_db_refused(self):
  with self.assertRaises(c.Refused):c.materialize(b'not sqlite',b'')
 def test_invalid_workflow_json_refused(self):
  t,p,db=self.fixture()
  try:
   db.execute("UPDATE workflow_entity SET nodes='invalid'");db.commit()
   with self.assertRaises(json.JSONDecodeError):c.scan_database(c.materialize(p.read_bytes(),b''),TERMS)
  finally:db.close();t.cleanup()
 def test_inactive_record_not_claimed_consumed(self):
  t,p,db=self.fixture()
  try:
   db.execute('UPDATE workflow_entity SET active=0');db.commit();r=c.scan_database(c.materialize(p.read_bytes(),b''),TERMS)
   self.assertTrue(all(x['active'] is False and x['actually_consumed'].startswith('NOT_PROVEN') for x in r['matches']))
  finally:db.close();t.cleanup()
 def test_ip_boundary(self):
  self.assertFalse(c.hits('172.25.0.20',TERMS));self.assertTrue(c.hits('http://172.25.0.2:8080/',TERMS))
 def test_mac_boundary(self):
  self.assertTrue(c.hits('82:fb:9a:73:0e:36',TERMS));self.assertFalse(c.hits('82:fb:9a:73:0e:36:ab',TERMS))

class NATTests(unittest.TestCase):
 def fixture(self,counter=7,chain='DOCKER'):
  return json.dumps({'nftables':[{'chain':{'family':'ip','table':'nat','name':'PREROUTING','hook':'prerouting','prio':-100}},
   {'chain':{'family':'ip','table':'nat','name':chain}},
   {'rule':{'family':'ip','table':'nat','chain':'PREROUTING','expr':[{'jump':{'target':chain}}]}},
   {'rule':{'family':'ip','table':'nat','chain':chain,'comment':'DO_NOT_LEAK','expr':[{'counter':{'packets':counter,'bytes':123}},{'match':{'left':{'payload':{'protocol':'tcp','field':'dport'}},'right':8081}},{'dnat':{'addr':'172.25.0.2','port':8080}}]}}]}).encode()
 def test_nft_jump_chain_hook_target(self):
  r=c.nft_evidence(self.fixture(),IDENT);self.assertEqual(len(r['chains']),2)
  self.assertIn('prerouting',json.dumps(r));self.assertIn('172.25.0.2',json.dumps(r));self.assertNotIn('DO_NOT_LEAK',json.dumps(r))
 def test_nft_counter_normalization(self):
  a=c.nft_evidence(self.fixture(1),IDENT);b_=c.nft_evidence(self.fixture(5000),IDENT)
  self.assertEqual(a['structure_sha256'],b_['structure_sha256'])
 def test_manual_not_claimed_docker(self):
  r=c.nft_evidence(self.fixture(chain='CUSTOM'),IDENT)
  self.assertTrue(all(x['ownership']!='DOCKER_CHAIN_CONSISTENT' for x in r['chains']))
 def test_iptables_target_and_comment(self):
  raw=b'*nat\n:PREROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n-A PREROUTING -j DOCKER\n-A DOCKER -p tcp --dport 8081 -m comment --comment DO_NOT_LEAK -j DNAT --to-destination 172.25.0.2:8080\nCOMMIT\n'
  r=c.iptables_evidence(raw,IDENT);self.assertEqual(len(r['chains']),2);self.assertNotIn('DO_NOT_LEAK',json.dumps(r));self.assertIn('172.25.0.2',json.dumps(r))
 def test_iptables_counters(self):
  raw=b'*nat\n:DOCKER - [1:2]\n-A DOCKER -c 1 2 -p tcp --dport 8081 -j DNAT --to-destination 172.25.0.2:8080\nCOMMIT\n'
  a=c.iptables_evidence(raw,IDENT);b_=c.iptables_evidence(raw.replace(b'-c 1 2',b'-c 3 4').replace(b'[1:2]',b'[3:4]'),IDENT)
  self.assertEqual(a['structure_sha256'],b_['structure_sha256'])
 def test_ipv6_empty_is_explicit(self):
  self.assertEqual(c.iptables_evidence(b'*nat\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n',IDENT)['chains'],[])
 def test_invalid_json(self):
  with self.assertRaises(json.JSONDecodeError):c.nft_evidence(b'bad',IDENT)

class LifecycleTests(unittest.TestCase):
 def test_late_interrupt_preserves_results_manifest(self):
  result={}
  def stop():raise KeyboardInterrupt()
  m=c.run_sections([('first',lambda:{'ok':True}),('second',stop)],lambda n,d:result.setdefault(n,d))
  self.assertEqual(m['status'],'INCOMPLETE');self.assertEqual(result['first.json']['status'],'OK');self.assertIn('manifest.json',result)
 def test_exception_no_secret_and_remaining_sections(self):
  result={}
  def fail():raise RuntimeError('TOKEN_DO_NOT_LEAK')
  m=c.run_sections([('first',fail),('second',lambda:42)],lambda n,d:result.setdefault(n,d))
  self.assertEqual(m['status'],'INCOMPLETE');self.assertEqual(result['second.json']['status'],'OK');self.assertNotIn('TOKEN_DO_NOT_LEAK',json.dumps(result))
 def test_success_manifest_hashes(self):
  result={};m=c.run_sections([('first',lambda:1)],lambda n,d:result.setdefault(n,d))
  self.assertEqual(m['status'],'COMPLETE');self.assertEqual(m['sha256']['first.json'],c.sha(c.encode(result['first.json'])+b'\n'))
 def test_atomic_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
   try:
    c.atomic(fd,'one.json',{'ok':True});self.assertEqual(stat.S_IMODE((Path(d)/'one.json').stat().st_mode),0o600)
    with self.assertRaises(FileExistsError):c.atomic(fd,'one.json',{'bad':True})
    self.assertEqual(json.loads((Path(d)/'one.json').read_text()),{'ok':True})
   finally:os.close(fd)
 def test_atomic_symlink_no_follow(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'target').write_text('unchanged');(p/'one.json').symlink_to(p/'target');fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
   try:
    with self.assertRaises(FileExistsError):c.atomic(fd,'one.json',{})
    self.assertEqual((p/'target').read_text(),'unchanged')
   finally:os.close(fd)
 def test_command_timeout(self):
  with self.assertRaises(TimeoutError):c.command([sys.executable,'-c','import time;time.sleep(5)'],timeout=.05)
 def test_command_error_redacted(self):
  with self.assertRaises(c.Refused) as ctx:c.command([sys.executable,'-c','import sys;sys.stderr.write("DO_NOT_LEAK");sys.exit(1)'])
  self.assertNotIn('DO_NOT_LEAK',str(ctx.exception))
 def test_command_large_output(self):
  with self.assertRaises(c.Refused):c.command([sys.executable,'-c','print("x"*100000)'],limit=1000)
 def test_missing_program(self):
  with self.assertRaises(FileNotFoundError):c.command(['/absent-v12-fixture'])
 def test_source_hash_apparmor(self):
  self.assertEqual(c.sha(base64.b64decode(c.APPARMOR_SOURCE_B64)),c.APPARMOR_SHA256)
 def test_apparmor_tamper(self):
  with patch.object(c,'APPARMOR_SHA256','0'*64):
   with self.assertRaises(c.Refused):c.apparmor()
 def test_docker_mutation_rejected(self):
  with self.assertRaises(c.Refused):c.docker('/containers/x/start')
 def test_root_entry_refuses_user(self):
  with patch.object(c.os,'geteuid',return_value=1001):
   with self.assertRaises(c.Refused):c.main()

class AdditionalTests(unittest.TestCase):
 def test_bootstrap_wrong_fixed_path_before_creation(self):
  with patch.object(b.os,'geteuid',return_value=0),patch.object(b.sys,'argv',['bootstrap','/tmp/unapproved','a'*64]),patch.object(b.tempfile,'mkdtemp') as make:
   with self.assertRaises(b.Refused):b.main()
   make.assert_not_called()
 def test_read_permission_error_not_no_match(self):
  with patch.object(c.os,'open',side_effect=PermissionError('fixture')):
   with self.assertRaises(PermissionError):c.read('/fixture')
 def test_launcher_exactly_one_bound_sudo(self):
  import shlex
  from command_v12 import build,SOURCE
  boot=b'print("fixture")'
  args=shlex.split(build(boot,hashlib.sha256(boot).hexdigest(),'a'*64));remote=shlex.split(args[-1])
  self.assertEqual(remote[:5],['sudo','/usr/bin/python3','-I','-B','-c'])
  self.assertEqual(remote[-2:],[SOURCE,'a'*64]);self.assertIn('StrictHostKeyChecking=yes',args)
 def test_launcher_tamper_refused(self):
  from command_v12 import build
  with self.assertRaises(ValueError):build(b'bad','0'*64,'a'*64)
 def test_linux_real_acl_rejected(self):
  import shutil,subprocess
  if not sys.platform.startswith('linux'):self.skipTest('real Linux ACL test runs on server')
  tool=shutil.which('setfacl');self.assertIsNotNone(tool)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'stage';p.mkdir(mode=0o700)
   subprocess.run([tool,'-m','u:65534:r-x',str(p)],check=True)
   with self.assertRaises(b.Refused):b.trusted_dir(p,os.getuid())
 def test_database_expressions_are_not_executed(self):
  t,p,db=DBTests().fixture()
  try:
   nodes=[{'parameters':{'url':'={{$env.PRIVATE_URL}}'},'credentials':{'httpHeaderAuth':{'id':'DO_NOT_LEAK'}}}]
   db.execute('UPDATE workflow_entity SET nodes=?',(json.dumps(nodes),));db.commit()
   result=c.scan_database(c.materialize(p.read_bytes(),b''),TERMS)
   self.assertEqual(len(result['unresolved_indirections']),2)
   self.assertNotIn('DO_NOT_LEAK',json.dumps(result));self.assertNotIn('PRIVATE_URL',json.dumps(result))
  finally:db.close();t.cleanup()
 def test_rule_order_is_preserved(self):
  d=json.loads(NATTests().fixture());d['nftables'].append({'rule':{'family':'ip','table':'nat','chain':'DOCKER','expr':[{'match':{'right':9999}},{'dnat':{'addr':'192.0.2.99','port':9999}}]}})
  result=c.nft_evidence(json.dumps(d).encode(),IDENT)
  row=next(x for x in result['chains'] if x['chain']=='DOCKER')
  self.assertEqual([x['ordinal'] for x in row['rules']],[0,1]);self.assertNotIn('192.0.2.99',json.dumps(result))
 def test_sigterm_equivalent_partial_manifest(self):
  out={}
  def interrupted():raise KeyboardInterrupt()
  m=c.run_sections([('first',lambda:1),('later',interrupted)],lambda n,v:out.setdefault(n,v))
  self.assertEqual(m['status'],'INCOMPLETE');self.assertIn('first.json',out)
 def test_read_directory_and_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(c.Refused):c.read(d)
   p=Path(d)/'link';p.symlink_to('/etc/passwd')
   with self.assertRaises(OSError):c.read(p)

if __name__=='__main__':unittest.main()
