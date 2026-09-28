import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import collector_v10 as c

class Tests(unittest.TestCase):
 def test_marker_suppresses_originals_and_secrets(self):
  raw=json.dumps({'status':'CHECKPOINT','capsule_sha256':'a'*64,'originals':{'env':'TEST_SECRET'},'steps':[{'phase':'backup','status':'DONE','before':{'token':'TEST_SECRET'}}]}).encode()
  r=c.marker_projection(raw);self.assertEqual(r['steps'],[{'status':'DONE','phase':'backup'}]);self.assertNotIn('TEST_SECRET',json.dumps(r))
 def test_marker_unknown_status_not_echoed(self):
  self.assertEqual(c.marker_projection(b'{"status":"TEST_SECRET","phase":"TEST_SECRET"}'),{})
 def test_semantic_safe_change_actor_unknown(self):
  a=c.unit_semantics(b'[Service]\nRestart=no\n');b=c.unit_semantics(b'[Service]\nRestart=on-failure\n')
  d=c.semantic_diff(a,b);self.assertEqual(d['classification'],'FOREIGN_CHANGE_SEMANTICS_KNOWN_ACTOR_UNKNOWN');self.assertEqual(d['actor'],'UNATTRIBUTED')
 def test_documentation_is_nonruntime_metadata(self):
  a=c.unit_semantics(b'[Unit]\nDocumentation=file:old\n');b=c.unit_semantics(b'[Unit]\nDocumentation=file:new\n')
  d=c.semantic_diff(a,b);self.assertEqual(d['classification'],'FOREIGN_CHANGE_SEMANTICS_KNOWN_ACTOR_UNKNOWN');self.assertTrue(d['changes'][0]['metadata_only'])
 def test_semantic_exec_unresolved(self):
  a=c.unit_semantics(b'[Service]\nExecStart=/bin/true\n');b=c.unit_semantics(b'[Service]\nExecStart=/bin/false\n')
  self.assertEqual(c.semantic_diff(a,b)['classification'],'FOREIGN_CHANGE_UNRESOLVED')
 def test_semantic_credential_hidden(self):
  a=c.unit_semantics(b'[Service]\nEnvironment=TOKEN=TEST_SECRET_ONE\n');b=c.unit_semantics(b'[Service]\nEnvironment=TOKEN=TEST_SECRET_TWO\n')
  self.assertNotIn('TEST_SECRET',json.dumps(c.semantic_diff(a,b)))
 def test_inventory_keeps_dash_name_not_description(self):
  self.assertEqual(c.inventory_projection(b'-.mount loaded active mounted DO_NOT_EXPORT_DESCRIPTION\n'),[['-.mount','loaded','active','mounted']])
 def test_unit_failure_does_not_discard_later(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'r',fixture=True)
   try:
    with patch.object(c,'run',return_value={'status':'INCOMPLETE','stdout':{'sanitized':None}}):
     rc=c.Collector(o).execute([('missing',lambda:c.unit_record('missing.service')),('later',lambda:{'ok':True})])
    self.assertEqual(rc,2);self.assertTrue((o.path/'later.json').exists())
   finally:o.close()
 def test_export_binds_every_result(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'r',fixture=True)
   try:
    c.Collector(o).execute([('one',lambda:{'safe':True})]);bundle=json.loads(gzip.decompress(base64.b64decode(c.export_results(o))))
    self.assertEqual(set(bundle),set(o.files))
    for name,x in bundle.items():self.assertEqual(hashlib.sha256(c.encode(x['value'])).hexdigest(),x['sha256'])
   finally:o.close()
 def test_changed_result_export_refused(self):
  with tempfile.TemporaryDirectory() as t:
   o=c.Output(Path(t)/'r',fixture=True)
   try:
    o.put('one.json',{});(o.path/'one.json').write_text('{"changed":true}')
    with self.assertRaises(c.Refused):c.export_results(o)
   finally:o.close()
 def test_read_symlink_refused(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'a';p.write_text('test');q=Path(t)/'b';q.symlink_to(p)
   with self.assertRaises(OSError):c.read_regular(q)
 def test_read_directory_refused(self):
  with tempfile.TemporaryDirectory() as t:
   with self.assertRaises((c.Refused,IsADirectoryError)):c.read_regular(t)
 def test_read_size_bound(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'a';p.write_text('too large')
   with self.assertRaises(c.Refused):c.read_regular(p,1)
 def test_interrupt_not_swallowed(self):
  def stop():raise InterruptedError()
  with self.assertRaises(InterruptedError):c.attempt(stop)
 def test_no_root_execution_without_binding(self):
  with patch.object(c.os,'geteuid',return_value=0),patch.object(c,'Output') as output,patch('builtins.print'):
   self.assertEqual(c.main(),70);output.assert_not_called()
 def test_no_subprocess_shell_evaluation(self):
  import inspect
  s=inspect.getsource(c.run);self.assertIn('subprocess.Popen(args',s);self.assertNotIn('shell=True',s)
 def test_no_no_mutation_inference(self):
  import inspect
  self.assertIn("'classification':'UNRESOLVED'",inspect.getsource(c.main))
 def test_journal_unit_attribution_without_payload(self):
  x=c.journal_line(json.dumps({'MESSAGE':'mychatbuddy-private-alpha.service: Main process exited, status=75/TEST_SECRET','SYSLOG_IDENTIFIER':'systemd'}).encode())
  self.assertTrue(x['mychatbuddy_reference']);self.assertIn('EXIT_75',x['labels']);self.assertNotIn('TEST_SECRET',json.dumps(x))

if __name__=='__main__':unittest.main()
