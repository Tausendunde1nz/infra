import json,sys,unittest
from unittest.mock import patch
import broker_v11 as b

class BrokerTests(unittest.TestCase):
 def test_exact_arguments(self):
  for op in b.COMMANDS:self.assertEqual(b.parse([op]),op)
  for args in [[],['status','x'],['/bin/sh'],['status;id'],['mychatbuddy-start'],['migration-confirm'],['-h'],['containers','--all']]:
   with self.assertRaises(b.Refused):b.parse(args)
 def test_systemctl_separator(self):
  a=b.COMMANDS['status'];self.assertEqual(a[a.index('--')+1:],b.UNITS)
 def test_readonly_allowlist(self):
  self.assertEqual(set(b.COMMANDS),{'status','containers','journal-counts'})
  for a in b.COMMANDS.values():self.assertTrue(a[0].startswith('/usr/bin/'));self.assertNotIn('sh',a)
 def test_sudoers_no_wildcards(self):
  s=b.sudoers();self.assertNotIn('*',s);self.assertEqual(s.count('NOPASSWD: NOSETENV:'),3);self.assertNotIn('NOPASSWD: ALL',s)
 def test_containers_no_env_or_payload(self):
  raw=json.dumps([{'Name':'/'+n,'State':{'Running':True,'Health':{'Status':'healthy','Log':[{'Output':'SECRET'}]}},'RestartCount':0,'Config':{'Env':['TOKEN=SECRET']}} for n in b.NAMES]).encode()
  out=json.dumps(b.sanitize('containers',raw));self.assertNotIn('SECRET',out);self.assertNotIn('Env',out)
 def test_wrong_container_set(self):
  with self.assertRaises(b.Refused):b.sanitize('containers',b'[]')
 def test_journal_message_suppression(self):
  raw=json.dumps({'_SYSTEMD_UNIT':b.UNITS[0],'PRIORITY':'3','MESSAGE':'TOKEN=SECRET','ENV':'SECRET'}).encode();out=json.dumps(b.sanitize('journal-counts',raw));self.assertNotIn('SECRET',out);self.assertIn('count',out)
 def test_unknown_journal_unit(self):self.assertEqual(b.sanitize('journal-counts',b'{"_SYSTEMD_UNIT":"secret.service","PRIORITY":"3"}'),[])
 def test_status_allowlist(self):
  raw='\n\n'.join('Id='+u+'\nActiveState=active\nMainPID=1\nEnvironment=SECRET' for u in b.UNITS).encode();self.assertNotIn('SECRET',json.dumps(b.sanitize('status',raw)))
 def test_invalid_json(self):
  with self.assertRaises(ValueError):b.sanitize('containers',b'bad')
 def test_no_command_passthrough(self):
  with self.assertRaises(b.Refused):b.run(('/bin/sh','-c','id'))
 def test_timeout_cleanup(self):
  cmd=(sys.executable,'-I','-B','-c','import time;time.sleep(30)')
  with patch.dict(b.COMMANDS,{'fixture':cmd}):
   with self.assertRaises(b.Refused):b.run(cmd,timeout=.1)
 def test_output_limit(self):
  cmd=(sys.executable,'-I','-B','-c','print("x"*10000)')
  with patch.dict(b.COMMANDS,{'fixture':cmd}):
   with self.assertRaises(b.Refused):b.run(cmd,limit=100)
 def test_stderr_not_returned(self):
  cmd=(sys.executable,'-I','-B','-c','import sys;sys.stderr.write("SECRET");print("ok")')
  with patch.dict(b.COMMANDS,{'fixture':cmd}):self.assertEqual(b.run(cmd).strip(),b'ok')

class CallerAuditTest(unittest.TestCase):
 def test_rejected_entry_does_not_claim_verified_caller(self):
  import contextlib,io,json
  from unittest.mock import patch
  import broker_v11 as b
  records=[]
  with patch.object(b.os,'geteuid',return_value=1001),patch.object(b.syslog,'openlog'),patch.object(b.syslog,'closelog'),patch.object(b.syslog,'syslog',side_effect=lambda level,text:records.append(json.loads(text))),contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(b.main(),77)
  self.assertEqual(records[0]['caller'],'unverified');self.assertIsNone(records[0]['uid'])
if __name__=='__main__':unittest.main()
