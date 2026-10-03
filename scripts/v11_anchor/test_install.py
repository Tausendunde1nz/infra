import os,sys,unittest,tempfile,shutil,subprocess
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_dispatcher'),str(HERE.parent/'v11_guard_recovery')]
from anchor import *
import manager,phase0,install
from publication import Journal
class Fake:
 def __init__(self):
  self.p=manager.profile('validation');self.calls=[];self.fail=False
  self.rows={r:{k:'' for k in manager.PROPS} for r in ('anchor','watch','consumer')}
  for role,row in self.rows.items():row.update(Id=self.p[role],LoadState='not-found' if role!='consumer' else 'loaded',ActiveState='inactive',SubState='dead',NeedDaemonReload='no',MainPID='0',Result='success')
 def __call__(self,args,**kw):
  self.calls.append(args);verb=args[3]
  if self.fail:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'private error')
  role=next((r for r in self.rows if self.p[r]==args[-1]),None)
  if verb=='show':return SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in self.rows[role].items())+'\n').encode(),stderr=b'')
  if verb=='enable':self.rows[role]['UnitFileState']='enabled-runtime'
  if verb=='disable':self.rows[role]['UnitFileState']='disabled'
  if verb=='start':self.rows[role]['ActiveState']='active' if role=='watch' else 'inactive'
  if verb=='stop':self.rows[role]['ActiveState']='inactive'
  return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
class ManagerTests(unittest.TestCase):
 def setUp(self):self.fake=Fake();self.events=[];self.closed=[];self.m=manager.Manager('validation',self.events.append,lambda:self.closed.append(True),self.fake)
 def test_scope(self):
  for action,role in [('restart','anchor'),('stop','consumer'),('start','--help'),('reload','anchor')]:
   with self.assertRaises(Refused):self.m.action(action,role)
  self.assertFalse(self.fake.calls)
 def test_fixed_commands_and_independent_observation(self):
  self.m.action('daemon-reload');self.m.action('enable','anchor');self.m.action('start','watch');self.m.action('stop','watch')
  self.assertEqual(len(self.events),8)
  for args in self.fake.calls:self.assertEqual(args[:3],('/usr/bin/systemctl','--no-pager','--no-ask-password'))
 def test_low_level_transport_has_no_scope_escape(self):
  for args in (('stop','--','ssh.service'),('daemon-reexec',),('start','--','tu1nz_delete_guard.service'),('show','--property=Environment','--',self.m.p['anchor'])):
   with self.assertRaisesRegex(Refused,'FIXED_TRANSPORT_SCOPE'):self.m.call(args)
  self.assertEqual(self.fake.calls,[])
 def test_nonzero_closes(self):
  self.fake.fail=True
  with self.assertRaises(Refused):self.m.action('start','watch')
  self.assertTrue(self.closed)
 def test_self_stop_refused(self):
  self.fake.rows['anchor']['MainPID']=str(os.getpid())
  with self.assertRaisesRegex(Refused,'SELF_STOP'):self.m.action('stop','anchor')
  self.assertTrue(all(a[3]=='show' for a in self.fake.calls))
 def test_templates_fixed_watch_target(self):
  t=manager.templates('validation','a'*64,'/usr/bin/python3.12');self.assertIn(b'Unit=tu1nz-v11-validation-anchor.service',t['tu1nz-v11-validation-watch.timer']);self.assertNotIn(b'tu1nz-v11-dispatcher.service',b''.join(t.values()))
 def test_interpreter_symlink_name_not_accepted(self):
  with self.assertRaises(Refused):manager.templates('validation','a'*64,'/usr/bin/python3')
 def test_production_and_validation_names_disjoint(self):self.assertFalse(set(manager.templates('production','a'*64,'/usr/bin/python3.12'))&set(manager.templates('validation','a'*64,'/usr/bin/python3.12')))
 def test_foreign_pending_reload_blocks(self):
  with self.assertRaisesRegex(Refused,'FOREIGN_PENDING'):manager.no_foreign_reload('Id=ssh.service\nNeedDaemonReload=yes\n',{'tu1nz-v11-validation-anchor.service'})
  self.assertTrue(manager.no_foreign_reload('Id=ssh.service\nNeedDaemonReload=no\n',set()))
 def test_loaded_not_stored_proof(self):
  with self.assertRaisesRegex(Refused,'NOT_LOADED'):self.m.verify('a'*64,'/usr/bin/python3.12')
class InstallTests(unittest.TestCase):
 def setUp(self):
  self.a=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.a.rmdir();self.r=Path(tempfile.mkdtemp(prefix='tu1nz-fence-files-',dir='/tmp'));self.r.chmod(0o700)
  phase0.prepare(self.a,b'anchor',[b'worker'],'/usr/bin/python3.12','a'*64,['/run/phase1-test'],fixture=True);self.s=Store(self.a,fixture=True);self.j=Journal(self.a/'phase0-journal',create=True)
  p=self.r/'run/systemd/system';p.mkdir(parents=True);[x.chmod(0o755) for x in [self.r/'run',self.r/'run/systemd',p]]
  self.f=install.file_backend('validation',self.r,True);self.fake=Fake();self.m=manager.Manager('validation',self.s.record,self.s.close_fence,self.fake)
  self.m.verify=lambda *a: 'b'*64
  self.i=install.Install(self.s,self.j,self.f,self.m,'validation')
 def tearDown(self):self.j.close();self.s.close();shutil.rmtree(self.a);shutil.rmtree(self.r)
 def test_install_and_idempotency(self):
  self.assertEqual(self.i.run(),'PHASE0_PUBLISHED');self.assertEqual(self.i.verify_start(),'PHASE0_VERIFIED');self.assertEqual(self.i.run(),'PHASE0_VERIFIED');self.assertFalse(self.s.exists('phase1.json'))
 def test_existing_file_never_overwritten(self):
  p=self.f.path(self.f.targets[0]);p.write_bytes(b'foreign');p.chmod(0o644)
  with self.assertRaisesRegex(Refused,'PREEXISTING'):self.i.run()
  self.assertEqual(p.read_bytes(),b'foreign')
 def test_running_consumer_refused(self):
  self.fake.rows['consumer']['ActiveState']='active'
  with self.assertRaisesRegex(Refused,'PRESTATE'):self.i.run()
 def test_incomplete_phase0_does_not_admit_phase1(self):
  self.i.run();self.assertFalse(self.s.exists('phase0.json'))
if __name__=='__main__':unittest.main()
