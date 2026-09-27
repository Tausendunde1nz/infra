"""Offline fake fixtures only. No sudo, journals, production commands or messages."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
FROZEN=BASE.parent/'backup_notify_v2'
if not FROZEN.exists():FROZEN=BASE.parent/'backup-notify-v2-20260927'
sys.path[:0]=[str(BASE),str(FROZEN/'vendor')]
import bashlex
import engine_v3 as e
spec=importlib.util.spec_from_file_location('reader_v2_guard',FROZEN/'reader_runtime.py')
guard=importlib.util.module_from_spec(spec);sys.modules['reader_v2_guard']=guard;spec.loader.exec_module(guard)
import runtime_v3 as rt

class V3Tests(unittest.TestCase):
 def sinks(self,s):return e.sink_matrix(s.encode(),bashlex)
 def projection(self,s,path='/usr/local/bin/wrapper'):
  return e.caller_projection(s.encode(),path,bashlex,{e.TARGET,'/usr/local/bin/wrapper'})
 def test_direct(self):self.assertEqual(self.projection(e.TARGET)['edges'][0]['kind'],'EXEC')
 def test_source(self):
  for word in ('source','.'):
   self.assertEqual(self.projection(word+' '+e.TARGET)['edges'][0]['kind'],'SOURCE')
 def test_shell_wrapper(self):self.assertEqual(self.projection('/bin/bash '+e.TARGET)['edges'][0]['kind'],'WRAPPER')
 def test_static_variable_wrapper(self):self.assertEqual(self.projection('P='+e.TARGET+'\n"$P"')['edges'][0]['target'],e.TARGET)
 def test_dynamic_unknown(self):self.assertTrue(self.projection('"$PROGRAM"')['unknown'])
 def test_text_not_call(self):
  p=self.projection('echo '+e.TARGET);self.assertFalse(p['edges']);self.assertTrue(p['text_reference'])
 def test_path_lookup_uncertain(self):self.assertEqual(self.projection('backup_notify.sh')['edges'][0]['resolution'],'PATH_LOOKUP_UNKNOWN')
 def test_systemd_direct(self):self.assertEqual(self.projection('[Service]\nExecStart='+e.TARGET,'/etc/systemd/system/test.service')['edges'][0]['target'],e.TARGET)
 def test_systemd_shell(self):self.assertEqual(self.projection('[Service]\nExecStart=/bin/sh -c "'+e.TARGET+'"','/etc/systemd/system/test.service')['edges'][0]['target'],e.TARGET)
 def test_root_cron(self):self.assertTrue(self.projection('0 * * * * root '+e.TARGET,'/etc/cron.d/test')['root_cron'])
 def test_user_cron_ignored(self):self.assertFalse(self.projection('0 * * * * nobody '+e.TARGET,'/etc/cron.d/test')['edges'])
 def test_root_crontab(self):self.assertTrue(self.projection('@daily '+e.TARGET,'/var/spool/cron/crontabs/root')['root_cron'])
 def test_chain(self):
  ns={'/entry':{'edges':[{'target':'/wrapper','resolution':'FIXED'}]},'/wrapper':{'edges':[{'target':e.TARGET,'resolution':'FIXED'}]}}
  d=e.graph_decision(ns,[{'path':'/entry','root':True,'active':True}])
  self.assertTrue(d['active_root_call_proved']);self.assertEqual(d['chains'][0]['chain'],['/entry','/wrapper',e.TARGET])
 def test_inactive(self):self.assertEqual(e.graph_decision({},[{'path':'/entry','root':True,'active':False}])['classification'],'NO_ACTIVE_ROOT_CALLER')
 def test_unknown_not_proven(self):
  d=e.graph_decision({'/entry':{'edges':[],'unknown':True}},[{'path':'/entry','root':True,'active':True}]);self.assertFalse(d['active_root_call_proved']);self.assertEqual(d['classification'],'ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN')
 def test_cycle_terminates(self):
  d=e.graph_decision({'/a':{'edges':[{'target':'/a','resolution':'FIXED'}],'unknown':True}},[{'path':'/a','active':True,'root':True}]);self.assertEqual(len(d['uncertain_root_entries']),1)
 def test_categories(self):
  rows=self.sinks('curl x\ngrep a b\nlogger x\ntest -f x\n')['commands']
  self.assertEqual([r['function'] for r in rows],['NETWORK','BACKUP_STATUS','LOGGING','FILE_CHECK'])
 def test_all_argument_positions_tainted(self):
  r=self.sinks('X=$(cat '+e.ENV+')\ncurl "$X" "$X" "$X"\n')
  row=next(r for r in r['commands'] if r['function']=='NETWORK')
  self.assertEqual([a['origin'] for a in row['arguments']],['ENV_TAINTED']*3)
 def test_derived(self):
  r=self.sinks('X=$(cat '+e.ENV+')\nY="$X"\nprintf "%s" "$Y"\n');self.assertEqual(r['commands'][-1]['arguments'][-1]['origin'],'DERIVED_FROM_ENV')
 def test_file_derived(self):
  r=self.sinks('X=$(cat /fixture)\nprintf "%s" "$X"\n');self.assertEqual(r['commands'][-1]['arguments'][-1]['origin'],'FILE_DERIVED')
 def test_unknown(self):self.assertEqual(self.sinks('printf "%s" "$UNSET"')['commands'][0]['arguments'][-1]['origin'],'UNKNOWN')
 def test_redirection(self):self.assertEqual(self.sinks('printf x >/var/log/fixture')['commands'][0]['redirection_categories'],['LOG_PATH'])
 def test_shell_eval(self):
  for x in ('eval x','source /fixture','. /fixture','bash -c x','sh -c x'):self.assertTrue(self.sinks(x)['commands'][0]['shell_evaluation'])
 def test_secret_suppression(self):
  token='SECRET_SENTINEL_927'
  r=self.sinks('X='+token+'\n/opt/'+token+' "$X" "https://'+token+'" > /tmp/'+token+'\n')
  self.assertNotIn(token,json.dumps(r));self.assertNotIn('https:',json.dumps(r))
 def test_no_execution(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp)/'CANARY';self.sinks('X=$(touch '+str(target)+')\nsource /definitely/absent\n');self.assertFalse(target.exists())
 def test_parser_failure_unknown(self):self.assertEqual(self.sinks('x="unterminated')['status'],'UNKNOWN')
 def test_allowlist(self):self.assertEqual(e.strict_data_parser(b'ENABLED=1\nTIMEOUT_SECONDS=30\n'),{'enabled':True,'timeout_seconds':30})
 def test_reject_injections(self):
  for value in (b'$(id)',b'`id`',b'1;id',b'--help',b'../x',b'"1"',b"'1'",b'1\rid',b'1\nX=1'):
   with self.assertRaisesRegex(ValueError,'^invalid_data$'):e.strict_data_parser(b'ENABLED='+value+b'\nTIMEOUT_SECONDS=3')
 def test_missing_duplicate_unknown(self):
  for data in (b'ENABLED=1',b'ENABLED=1\nENABLED=1\nTIMEOUT_SECONDS=2',b'ENABLED=1\nTIMEOUT_SECONDS=2\nTOKEN=secret'):
   with self.assertRaisesRegex(ValueError,'^invalid_data$'):e.strict_data_parser(data)
 def test_quarantine_survives_rollback(self):
  p=e.quarantine_plan({'classification':'ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN'});self.assertEqual(p['automatic_rollback'],'KEEP_QUARANTINE');self.assertTrue(p['manual_original_recovery_only']);self.assertFalse(p['activation_ready'])
 def test_historical_preserved(self):self.assertEqual(e.quarantine_plan({'classification':'NO_ACTIVE_ROOT_CALLER'})['action'],'PRESERVE_HISTORICAL')
 def test_active_unit(self):
  r=rt.root_context('/etc/systemd/system/test.service',{}, {'test.service':{'User':'root','LoadState':'loaded','ActiveState':'inactive','UnitFileState':'enabled'}});self.assertTrue(r['active']);self.assertTrue(r['root'])
 def test_masked_unit(self):
  r=rt.root_context('/etc/systemd/system/test.service',{}, {'test.service':{'User':'root','LoadState':'loaded','ActiveState':'inactive','UnitFileState':'masked'}});self.assertFalse(r['active'])
 def test_timer_activates_service(self):
  s={'test.service':{'User':'root','LoadState':'loaded','ActiveState':'inactive','UnitFileState':'static','TriggeredBy':'test.timer'},'test.timer':{'ActiveState':'active'}}
  self.assertTrue(rt.root_context('/etc/systemd/system/test.service',{},s)['active'])
 def test_inactive_cron_unknown(self):self.assertEqual(rt.root_context('/etc/cron.d/test',{'root_cron':True},{})['active'],'UNKNOWN')
 def test_symlink_live_not_read(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'link';p.symlink_to('/etc/passwd');r=rt.live_identity(str(p),'',os.getuid(),set());self.assertFalse(r['hash_matches'])
 def test_env_never_read(self):
  with self.assertRaises(ValueError):rt.live_identity(e.ENV,'',0,set())

if __name__=='__main__':unittest.main()

class BundleTests(unittest.TestCase):
 def test_build_deterministic(self):
  import build_reader_v3 as b
  self.assertEqual(b.build(),(BASE/'tu1nz_backup_notify_reader_v3.py').read_bytes())
 def test_launcher_rejects_drift(self):
  import tu1nz_backup_notify_launcher_v3 as launch
  with self.assertRaises(ValueError):launch.remote_command(b'not pinned')
 def test_launcher_single_fixed_sudo(self):
  import tu1nz_backup_notify_launcher_v3 as launch
  command=launch.remote_command((BASE/'tu1nz_backup_notify_reader_v3.py').read_bytes())
  self.assertEqual(command.count("'sudo'"),1);self.assertIn('hashlib.sha256(b)',command)
  self.assertNotIn('shell=True',command);self.assertNotIn('restart',command)
 def test_live_missing(self):
  with tempfile.TemporaryDirectory() as tmp:
   r=rt.live_identity(str(Path(tmp).resolve()/'missing'),'x',os.getuid(),set())
   self.assertFalse(r['hash_matches'])
   if sys.platform=='linux':self.assertFalse(r['exists'])
   else:self.assertEqual(r['exists'],'UNKNOWN');self.assertEqual(r['error_class'],'AttributeError')
 def test_fixed_show_command(self):
  from types import SimpleNamespace
  with patch.object(rt,'guarded',return_value=b''),patch.object(rt.subprocess,'run',return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'Id=cron.service\nUser=root\nActiveState=active\n')) as run:
   result=rt.unit_states([],{ 'systemctl_sha256':'fixture'})
   self.assertEqual(result['cron.service']['ActiveState'],'active')
   args=run.call_args[0][0];self.assertEqual(args[:2],['/usr/bin/systemctl','show']);self.assertEqual(args[-1],'cron.service')
 def test_bad_unit_name(self):
  with patch.object(rt,'guarded',return_value=b''):
   with self.assertRaises(ValueError):rt.unit_states(['--all'],{'systemctl_sha256':'fixture'})
 def test_no_env_candidate(self):
  b=json.loads((FROZEN/'CALLER_BINDINGS.json').read_text())
  self.assertFalse(any(x['path'].endswith('/.env') for x in b['callers']))
 def test_linux_sealed_bundle(self):
  import subprocess
  if sys.platform!='linux':
   self.assertEqual(sys.platform,'darwin');return
  code="import importlib.util,sys; p=sys.argv[1]; s=importlib.util.spec_from_file_location('bundle',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); fd,parser,engine,runtime,b=m.load_bundle(); assert engine.sink_matrix(b'printf fixture',parser)['status']=='PROJECTED'; import fcntl; assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE; print('sealed_bundle_ok')"
  r=subprocess.run([sys.executable,'-I','-S','-B','-c',code,str(BASE/'tu1nz_backup_notify_reader_v3.py')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
  self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stdout,b'sealed_bundle_ok\n')

class CronHookTests(unittest.TestCase):
 def test_daily_hook_is_shell_not_crontab(self):
  r=e.caller_projection(('#!/bin/sh\n'+e.TARGET+'\n').encode(),'/etc/cron.daily/fixture',bashlex,{e.TARGET})
  self.assertEqual(r['edges'][0]['target'],e.TARGET)
  self.assertEqual(rt.root_context('/etc/cron.daily/fixture',r,{})['kind'],'HOOK')
