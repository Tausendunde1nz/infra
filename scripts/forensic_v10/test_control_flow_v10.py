import ast
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

class Tests(unittest.TestCase):
 def test_exact_bootstrap_refusal_before_explicit_writes(self):
  fixture=json.loads((Path(__file__).parent/'historical_bootstrap_fixture.json').read_text());source=fixture['source'];self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),fixture['source_sha256'])
  calls=[]
  class Refused(Exception):pass
  def checked(args,**kw):
   calls.append(args)
   if 'list-units' in args:return b'-.mount loaded active mounted Root Mount\n'
   self.assertEqual(args,['/usr/bin/systemctl','show','-.mount','-p','NeedDaemonReload','--value']);raise Refused('invalid option dot')
  def mutation(*args,**kw):raise AssertionError('persistent mutation reached')
  ns={'os':types.SimpleNamespace(geteuid=lambda:0,umask=lambda x:None,chdir=lambda x:None),'Refused':Refused,'validate_payload':lambda p:{},'DIRECTORIES':(Path('/fixture/root'),),'UNITS':Path('/fixture/units'),'checked':checked,'create_dir':mutation,'create_file':mutation,'private_json':mutation,'Store':mutation,'Transaction':mutation}
  exec(compile(source,'<hash-bound-historical-bootstrap>','exec'),ns)
  with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False):
   with self.assertRaises(Refused):ns['bootstrap']({},'a'*64)
  self.assertEqual(len(calls),2)
 def test_static_refusal_loop_has_no_cleanup_handler(self):
  source=json.loads((Path(__file__).parent/'historical_bootstrap_fixture.json').read_text())['source'];f=ast.parse(source).body[0]
  loop=next(n for n in f.body if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='name')
  self.assertFalse(any(isinstance(n,ast.Try) for n in ast.walk(loop)))
  store=next(n for n in f.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='store' for t in n.targets))
  self.assertLess(loop.lineno,store.lineno)
 def test_absolute_no_mutation_not_claimed(self):
  proof=json.loads((Path(__file__).parent/'control_flow_evidence.json').read_text())
  self.assertEqual(proof['classification'],'MUTATION_REACHABLE_BEFORE_REFUSAL');self.assertTrue(proof['implicit_import_cache_write_possible']);self.assertTrue(proof['live_corroboration_required'])

if __name__=='__main__':unittest.main()
