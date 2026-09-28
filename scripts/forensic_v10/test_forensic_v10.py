import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import collector_v10 as c

class Tests(unittest.TestCase):
 def test_root_mount(self):self.assertEqual(c.systemctl('show',['-.mount']),['/usr/bin/systemctl','--no-pager','show','--','-.mount'])
 def test_templates(self):self.assertEqual(c.systemctl('cat',['worker@.service','worker@name.service'])[-2:],['worker@.service','worker@name.service'])
 def test_escaped(self):self.assertEqual(c.systemctl('show',[r'var-lib-a\x2db.mount'])[-1],r'var-lib-a\x2db.mount')
 def test_leading_dash(self):self.assertEqual(c.systemctl('show',['-name.service'])[-2:],['--','-name.service'])
 def test_missing_unit_permitted_as_data(self):self.assertEqual(c.systemctl('show',['not-installed.service'])[-1],'not-installed.service')
 def test_empty_refused(self):
  for names in ([],[''],['one.service','']):
   with self.assertRaises(c.Refused):c.systemctl('show',names)
 def test_multiple(self):self.assertEqual(c.systemctl('show',['-.mount','a.service'])[-3:],['--','-.mount','a.service'])
 def test_options_before_separator(self):
  a=c.systemctl('show',['-.mount'],['NeedDaemonReload']);self.assertLess(a.index('-p'),a.index('--'));self.assertEqual(a[-1],'-.mount')
 def test_no_shell_syntax(self):
  for name in ('a;id.service','$(id).service','a\n.service','a b.service','../x.service'):
   with self.assertRaises(c.Refused):c.systemctl('cat',[name])
 def test_mutating_verbs_refused(self):
  for verb in ('start','restart','reload','daemon-reload','stop','enable','disable','set-property'):
   with self.assertRaises(c.Refused):c.systemctl(verb,['a.service'])
 def test_timeout(self):
  r=c.run([sys.executable,'-I','-S','-c','import time; time.sleep(5)'],timeout=.1);self.assertTrue(r['timeout']);self.assertEqual(r['status'],'INCOMPLETE')
 def test_exit_code(self):
  r=c.run([sys.executable,'-I','-S','-c','raise SystemExit(3)']);self.assertEqual(r['returncode'],3);self.assertEqual(r['status'],'INCOMPLETE')
 def test_invalid_json(self):
  r=c.run([sys.executable,'-I','-S','-c','print("broken")'],json.loads);self.assertEqual(r['exception_class'],'JSONDecodeError')
 def test_missing_program(self):self.assertEqual(c.run(['/nonexistent-v10-command'])['exception_class'],'FileNotFoundError')
 def test_large_output(self):
  r=c.run([sys.executable,'-I','-S','-c','print("x"*10000)'],limit=100);self.assertEqual(r['status'],'INCOMPLETE')
 def test_stream_partial_timeout(self):
  r=c.run([sys.executable,'-I','-S','-c','import time; print("{\\"n\\":1}",flush=True); time.sleep(5)'],stream=json.loads,timeout=.3)
  self.assertTrue(r['timeout']);self.assertEqual(r['stdout']['sanitized'],[{'n':1}])
 def test_secret_suppression(self):
  secret='TEST_ONLY_CREDENTIAL_987654321'
  r=c.run([sys.executable,'-I','-S','-c',f'import sys; print("{secret}"); print("{secret}",file=sys.stderr)'])
  self.assertNotIn(secret,json.dumps(r));self.assertEqual(r['status'],'INCOMPLETE')
 def test_unit_secret_suppression(self):
  x=c.unit_semantics(b'[Service]\nEnvironment=TOKEN=TEST_ONLY_SECRET\nExecStart=/usr/bin/foo --token TEST_ONLY_SECRET\nUser=chatops\n')
  self.assertNotIn('TEST_ONLY_SECRET',json.dumps(x));self.assertEqual(x['directives'][-1]['safe_value'],'chatops')
 def test_journal_secret_suppression(self):
  x=c.journal_line(json.dumps({'MESSAGE':'COMMAND=/usr/bin/python3 TOKEN=TEST_ONLY_SECRET','SYSLOG_IDENTIFIER':'sudo','_PID':'1'}).encode())
  self.assertNotIn('TEST_ONLY_SECRET',json.dumps(x))
 def test_manifest_and_partial(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'result',fixture=True);collector=c.Collector(o)
   def denied():raise PermissionError()
   try:
    rc=collector.execute([('first',lambda:{'ok':True}),('denied',denied),('last',lambda:{'ok':True})]);self.assertEqual(rc,2)
    self.assertEqual(json.loads((o.path/'manifest.json').read_text())['status'],'INCOMPLETE')
    for p in o.path.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
    self.assertEqual(o.path.stat().st_mode&0o777,0o700);self.assertTrue((o.path/'first.json').exists());self.assertTrue((o.path/'last.json').exists())
   finally:o.close()
 def test_interrupt_preserves_earlier(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'result',fixture=True)
   def stop():raise InterruptedError()
   try:
    self.assertEqual(c.Collector(o).execute([('first',lambda:True),('stop',stop),('later',lambda:True)]),2)
    self.assertTrue((o.path/'first.json').exists());self.assertFalse((o.path/'later.json').exists())
   finally:o.close()
 def test_success_manifest_hashes(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'result',fixture=True)
   try:
    self.assertEqual(c.Collector(o).execute([('first',lambda:True)]),0)
    m=json.loads((o.path/'manifest.json').read_text())
    for n,h in m['files'].items():self.assertEqual(hashlib.sha256((o.path/n).read_bytes()).hexdigest(),h)
   finally:o.close()
 def test_existing_output_refused(self):
  with tempfile.TemporaryDirectory() as t:
   with self.assertRaises(FileExistsError):c.Output(t,fixture=True)
 def test_symlink_output_refused(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'link';p.symlink_to(t)
   with self.assertRaises(FileExistsError):c.Output(p,fixture=True)
 def test_foreign_result_refused(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'result',fixture=True)
   try:
    (o.path/'first.json').write_text('foreign')
    with self.assertRaises(c.Refused):o.put('first.json',{})
    self.assertEqual((o.path/'first.json').read_text(),'foreign')
   finally:o.close()
 def test_atomic_failure_preserves_prior(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'result',fixture=True)
   try:
    o.put('first.json',{'ok':True});before=(o.path/'first.json').read_bytes()
    with patch.object(c.os,'replace',side_effect=OSError()):
     with self.assertRaises(OSError):o.put('second.json',{})
    self.assertEqual((o.path/'first.json').read_bytes(),before);self.assertFalse(list(o.path.glob('.tmp-*')))
   finally:o.close()
 def test_import_cache_mutation_witness(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'fixture.py';p.write_text('VALUE=1\n')
   code='import sys,importlib.util; sys.dont_write_bytecode=False; sys.pycache_prefix='+repr(str(Path(t)/'cache'))+'; p='+repr(str(p))+'; s=importlib.util.spec_from_file_location("fixture",p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)'
   subprocess.run([sys.executable,'-I','-S','-c',code],check=True)
   self.assertTrue(list((Path(t)/'cache').rglob('*.pyc')))
 def test_new_interpreter_B_prevents_cache(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'fixture.py';p.write_text('VALUE=1\n')
   code='import sys,importlib.util; sys.pycache_prefix='+repr(str(Path(t)/'cache'))+'; p='+repr(str(p))+'; s=importlib.util.spec_from_file_location("fixture",p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)'
   subprocess.run([sys.executable,'-I','-S','-B','-c',code],check=True);self.assertFalse((Path(t)/'cache').exists())

if __name__=='__main__':unittest.main()
