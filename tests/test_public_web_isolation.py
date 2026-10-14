"""Finite bootstrap contract tests; real Linux enforcement is a separate gate."""
import importlib.util
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('public_isolation',ROOT/'scripts/tu1nz_public_web_isolate_r1.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Contract(unittest.TestCase):
 def test_r2_plan_exact_private_staging_and_open_host_gates(self):
  plan=(ROOT/'docs/PUBLIC_WEB_DOCKER_ISOLATION_R1_HOST_PLAN.txt').read_text()
  addendum=(ROOT/'docs/PUBLIC_WEB_DOCKER_ISOLATION_R2_HOST_ADDENDUM.txt').read_text()
  self.assertIn('/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/',plan)
  self.assertNotIn('/var/log/tausendunde1nz/public-web-isolation-r1/<approved-transaction>',plan)
  for value in ('/opt/tu1nz_repos/lighting-halloween-r1/20261014-1',
                'tu1nz-public-isolation-r2-probe-s7.service',
                'tu1nz-public-isolation-r2-probe-s8-landing.service',
                'tu1nz-public-isolation-r2-probe-wms.service',
                'Current support/', 'remain OPEN'):
   self.assertIn(value,plan+'\n'+addendum)
  self.assertIn('no S8 ancestor/replay investigation',addendum)
  self.assertIn('No Host action/signature in Source session',addendum)
 def test_static_wms_collector_includes_new_dropin_directory(self):
  workflow=(ROOT/'.github/workflows/control-validation.yml').read_text()
  self.assertIn('cp -R systemd/tu1nz-adult-public-s10-* "$temporary_units/"',workflow)
  with tempfile.TemporaryDirectory(prefix='public-static-units-') as target:
   paths=sorted((ROOT/'systemd').glob('tu1nz-adult-public-s10-*'))
   subprocess.run(['/bin/cp','-R',*[str(p) for p in paths],target],check=True,capture_output=True)
   copied=Path(target)/'tu1nz-adult-public-s10-wms.service.d/zz-public-isolation-r1.conf'
   self.assertEqual(copied.read_bytes(),(ROOT/'systemd'/copied.parent.name/copied.name).read_bytes())

 def test_exact_profiles_no_arbitrary_program_pid_user_or_mapping(self):
  self.assertEqual(set(m.PROFILES),{'s7','s8-landing','wms'})
  for profile,(unit,command) in m.PROFILES.items():
   self.assertTrue(unit.endswith('.service'))
   self.assertTrue(command[0].startswith(m.APP+'/.venv/bin/'))
   raw=(ROOT/'systemd'/(unit+'.d')/'zz-public-isolation-r1.conf').read_text()
   self.assertIn('ExecStart=!/usr/bin/python3 -I -B -S /usr/local/bin/'+Path(m.__file__).name+' --profile '+profile,raw)
   self.assertIn('RestrictNamespaces=user',raw)
   self.assertIn('InaccessiblePaths=-/run/docker.sock -/run/containerd -/run/user/1001',raw)
   for arg in ('--command','--pid','--uid','--map'):
    result=subprocess.run([sys.executable,'-I','-B',m.__file__,'--profile',profile,arg,'1'],capture_output=True)
    self.assertEqual(result.returncode,125)
    self.assertNotIn(b'application_exec": true',result.stderr)

 def test_nonroot_denies_before_namespace_or_application(self):
  with patch.object(m.sys,'platform','linux'),patch.object(m.os,'geteuid',return_value=1001),patch.object(m.os,'fork') as fork:
   with self.assertRaisesRegex(m.Denied,'BOOTSTRAP_REQUIRED'):m.establish_namespace()
   fork.assert_not_called()

 def test_foreign_account_mapping_and_socket_activation_deny(self):
  account=Mock(pw_uid=1001);group=Mock(gr_gid=1001)
  with patch.object(m.sys,'platform','linux'),patch.object(m.os,'geteuid',return_value=0),\
       patch.object(m.pwd,'getpwnam',return_value=account),patch.object(m.grp,'getgrnam',return_value=group),\
       patch.object(m.os,'fork') as fork,patch.dict(os.environ,{},clear=True):
   account.pw_uid=1002
   with self.assertRaisesRegex(m.Denied,'ACCOUNT_BINDING'):m.establish_namespace()
   account.pw_uid=1001
   with patch.object(m,'mappings',return_value=[(0,1001,1)]),self.assertRaisesRegex(m.Denied,'INITIAL_MANAGER_NAMESPACE'):
    m.establish_namespace()
   with patch.dict(os.environ,{'LISTEN_FDS':'1'}),self.assertRaisesRegex(m.Denied,'SOCKET_ACTIVATION'):
    m.establish_namespace()
   fork.assert_not_called()

 def test_failed_group_drop_never_forks(self):
  with patch.object(m.sys,'platform','linux'),patch.object(m.os,'geteuid',return_value=0),\
       patch.dict(os.environ,{},clear=True),patch.object(m.pwd,'getpwnam',return_value=Mock(pw_uid=1001)),\
       patch.object(m.grp,'getgrnam',return_value=Mock(gr_gid=1001)),\
       patch.object(m,'mappings',return_value=[(0,0,4294967295)]),\
       patch.object(m.os,'setgroups',side_effect=PermissionError),patch.object(m.os,'fork') as fork:
   with self.assertRaises(PermissionError):m.establish_namespace()
   fork.assert_not_called()

 def test_primary_abort_cleanup_are_separate_and_sanitized(self):
  with patch.object(m.sys,'platform','linux'),patch.object(m.os,'geteuid',return_value=0),\
       patch.dict(os.environ,{},clear=True),patch.object(m.pwd,'getpwnam',return_value=Mock(pw_uid=1001)),\
       patch.object(m.grp,'getgrnam',return_value=Mock(gr_gid=1001)),\
       patch.object(m,'mappings',return_value=[(0,0,4294967295)]),patch.object(m.os,'setgroups'),\
       patch.object(m.os,'pipe2',side_effect=[(10,11),(12,13)],create=True),patch.object(m.os,'fork',return_value=123),\
       patch.object(m.os,'pidfd_open',return_value=14,create=True),\
       patch.object(m.select,'select',return_value=([],[],[])),patch.object(m.os,'close'),\
       patch.object(m.signal,'pidfd_send_signal',side_effect=OSError('PRIVATE_CANARY'),create=True) as kill,\
       patch.object(m.os,'waitpid',side_effect=OSError('PRIVATE_CANARY')):
   with self.assertRaises(m.Denied) as result:m.establish_namespace()
   error=result.exception
   self.assertEqual(error.primary,'PUBLIC_WEB_ISOLATION_NAMESPACE_CREATION_RED')
   self.assertEqual(error.abort,['PUBLIC_WEB_ISOLATION_OWNED_CREATOR_ABORT_RED'])
   self.assertEqual(error.cleanup,['PUBLIC_WEB_ISOLATION_OWNED_CREATOR_REAP_RED'])
   self.assertNotIn('CANARY',str(error));kill.assert_called_once_with(14,m.signal.SIGKILL,None,0)

 def test_reap_interruption_never_signals_reusable_numeric_pid(self):
  with ExitStack() as stack:
   stack.enter_context(patch.dict(os.environ,{},clear=True))
   mocks=(
    (m.sys,'platform',{'new':'linux'}),(m.os,'geteuid',{'return_value':0}),
    (m.pwd,'getpwnam',{'return_value':Mock(pw_uid=1001)}),(m.grp,'getgrnam',{'return_value':Mock(gr_gid=1001)}),
    (m,'mappings',{'return_value':[(0,0,4294967295)]}),(m.os,'setgroups',{}),
    (m.os,'pipe2',{'side_effect':[(10,11),(12,13)],'create':True}),(m.os,'fork',{'return_value':123}),
    (m.os,'pidfd_open',{'return_value':14,'create':True}),(m.os,'open',{'return_value':15}),
    (m.select,'select',{'return_value':([10],[],[])}),(m.os,'read',{'return_value':b'R'}),
    (m.Path,'write_text',{}),(m.os,'write',{}),(m.os,'close',{}),
    (m.ctypes,'CDLL',{'return_value':Mock(setns=Mock(return_value=0))}),
    (m.os,'waitpid',{'side_effect':[m.Denied('BOOTSTRAP_INTERRUPTED'),ChildProcessError]}))
   for obj,name,kwargs in mocks:stack.enter_context(patch.object(obj,name,**kwargs))
   handle_signal=stack.enter_context(patch.object(m.signal,'pidfd_send_signal',side_effect=ProcessLookupError,create=True))
   numeric_signal=stack.enter_context(patch.object(m.os,'kill'))
   with self.assertRaises(m.Denied) as result:m.establish_namespace()
   self.assertEqual(result.exception.primary,'PUBLIC_WEB_ISOLATION_BOOTSTRAP_INTERRUPTED')
   self.assertEqual(result.exception.abort,[])
   self.assertEqual(result.exception.cleanup,['PUBLIC_WEB_ISOLATION_OWNED_CREATOR_REAP_RED'])
   handle_signal.assert_called_once_with(14,m.signal.SIGKILL,None,0);numeric_signal.assert_not_called()

 def test_interruption_is_not_success_or_a_retry(self):
  with self.assertRaisesRegex(m.Denied,'BOOTSTRAP_INTERRUPTED'):m.interrupted(m.signal.SIGTERM,None)
  self.assertEqual(m.error_code(ValueError('PRIVATE_CANARY')),'PUBLIC_WEB_ISOLATION_START_DENIED')

 def test_credential_gate_denies_before_mount_or_read_when_namespace_not_private(self):
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'readlink',return_value='same'),\
       patch.object(m.ctypes,'CDLL') as libc:
   with self.assertRaisesRegex(m.Denied,'PRIVATE_MOUNT_NAMESPACE_REQUIRED'):
    m.prepare_credentials('tu1nz-adult-public-s7.service')
   libc.assert_not_called()

if __name__=='__main__':unittest.main()
