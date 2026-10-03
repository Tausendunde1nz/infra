import copy,unittest,subprocess
from types import SimpleNamespace
from unittest.mock import patch
from systemd_adapter import *
class Fake:
 def __init__(self):
  self.state={n:{k:'' for k in PROPERTIES} for n in NAMES};self.calls=[];self.failure=None;self.no_effect=False
  for n,v in self.state.items():v.update(Id=n,LoadState='loaded',ActiveState='inactive',SubState='dead',UnitFileState='disabled',NeedDaemonReload='no',Result='success',ExecMainStatus='0')
 def __call__(self,args,**kw):
  self.calls.append((args,kw));verb=args[3]
  if verb=='show':return SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in self.state[args[-1]].items())+'\n').encode(),stderr=b'')
  if self.failure=='timeout':raise subprocess.TimeoutExpired(args,30)
  if self.failure=='dbus':return SimpleNamespace(returncode=1,stdout=b'',stderr=b'private diagnostic not logged')
  if verb!='daemon-reload' and not self.no_effect:
   v=self.state[args[-1]]
   if verb=='start':v.update(ActiveState='active',SubState='running')
   elif verb=='stop':v.update(ActiveState='inactive',SubState='dead')
   elif verb=='enable':v['UnitFileState']='enabled'
   elif verb=='disable':v['UnitFileState']='disabled'
   elif verb=='mask':v.update(UnitFileState='masked-runtime',LoadState='masked')
   elif verb=='unmask':v.update(UnitFileState='disabled',LoadState='loaded')
  return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
class Adapter(unittest.TestCase):
 def setUp(self):self.fake=Fake();self.log=[];self.closed=[];self.a=Systemd(self.log.append,lambda:self.closed.append(True),self.fake)
 def test_fixed_actions_and_observations(self):
  for action,n in sorted(ALLOWED,key=str):
   self.a.action(action,n);self.assertEqual(self.log[-2]['stage'],'INTENT');self.assertEqual(self.log[-1]['stage'],'DONE')
  for args,kw in self.fake.calls:
   self.assertEqual(args[0],'/usr/bin/systemctl');self.assertEqual(kw['env'],ENV);self.assertEqual(kw['timeout'],30)
   if args[3]!='daemon-reload':self.assertIn('--',args)
 def test_scope_rejects_other_service_and_options(self):
  for n in ('ssh.service','--root=/tmp/x','../x',units.GUARD):
   with self.assertRaises(Refused):self.a.action('stop',n)
  self.assertEqual(self.fake.calls,[])
 def test_timeout_closes_and_reobserves(self):
  self.fake.failure='timeout'
  with self.assertRaises(Ambiguous):self.a.action('start',units.BOOT)
  self.assertTrue(self.closed);self.assertEqual(self.log[-1]['stage'],'AMBIGUOUS');self.assertIsNotNone(self.log[-1]['observed_sha256'])
 def test_dbus_failure_not_success(self):
  self.fake.failure='dbus'
  with self.assertRaises(Ambiguous):self.a.action('start',units.BOOT)
  self.assertTrue(self.closed);self.assertNotIn('private',str(self.log))
 def test_exit_zero_without_postcondition_rejected(self):
  self.fake.no_effect=True
  with self.assertRaises(Ambiguous):self.a.action('start',units.BOOT)
 def test_loaded_diff_closes_fence(self):
  expected={n:configuration(v) for n,v in self.fake.state.items()};self.a.verify_loaded(expected);self.fake.state[units.BOOT]['DropInPaths']='/run/systemd/system/foreign.conf'
  with self.assertRaises(Refused):self.a.verify_loaded(expected)
  self.assertTrue(self.closed)
 def test_daemon_reload_postcondition(self):
  self.fake.state[units.BOOT]['NeedDaemonReload']='yes'
  with self.assertRaises(Ambiguous):self.a.action('daemon-reload')
 def test_parse_rejects_duplicate_and_missing(self):
  for value in (b'Id=x\nId=x\n',b'',b'garbage',b'Unexpected=1\n'):
   with self.assertRaises(Refused):parse_show(value)
 def test_alias_rejected(self):
  self.fake.state[units.BOOT]['Id']='foreign.service'
  with self.assertRaises(Refused):self.a.show(units.BOOT)
 def test_existing_recovery_unit_never_displaced(self):
  with self.assertRaises(Refused):self.a.restore(copy.deepcopy(self.fake.state))
  self.assertEqual(self.fake.calls,[])
 def test_terminal_config_rechecked(self):
  before=copy.deepcopy(self.fake.state);self.a.verify_restored(before);self.fake.state[units.GUARD]['ExecStartPre']='foreign'
  with self.assertRaises(Refused):self.a.verify_restored(before)
 def test_execution_history_not_authority(self):
  v='{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; start_time=t ; stop_time=t ; pid=12 ; code=exited ; status=0 }'
  self.assertEqual(execution_identity(v),'{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }')
 def test_stop_self_pid_refused_before_mutation(self):
  self.fake.state[units.WORK]['MainPID']=str(os.getpid())
  with self.assertRaisesRegex(Refused,'RECOVERY_MUST_NOT_STOP_ITSELF'):self.a.action('stop',units.WORK)
  self.assertTrue(self.closed);self.assertTrue(all(a[3]=='show' for a,k in self.fake.calls))
 def test_stop_self_helper_cgroup_refused(self):
  with patch('systemd_adapter.current_units',return_value={units.WORK}):
   with self.assertRaisesRegex(Refused,'RECOVERY_MUST_NOT_STOP_ITSELF'):self.a.action('stop',units.WORK)
  self.assertTrue(self.closed)
 def test_restore_from_owned_worker_refused_before_any_mutation(self):
  before=copy.deepcopy(self.fake.state)
  for n in OWNED:before[n].update(LoadState='not-found',ActiveState='inactive')
  with patch('systemd_adapter.current_units',return_value={units.WORK}):
   with self.assertRaisesRegex(Refused,'EXTERNAL_ANCHOR'):self.a.restore(before)
  self.assertTrue(self.closed);self.assertTrue(all(a[3]=='show' for a,k in self.fake.calls))
 def test_cgroup_descendant_identified(self):
  with patch('systemd_adapter.Path.read_bytes',return_value=('0::/system.slice/'+units.WORK+'/helper\n').encode()):self.assertEqual(current_units(),{units.WORK})
 def test_malformed_cgroup_refused(self):
  with patch('systemd_adapter.Path.read_bytes',return_value=b'not-a-cgroup'):
   with self.assertRaises(Refused):current_units()
if __name__=='__main__':unittest.main()
