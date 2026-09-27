import json
import io
import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import tu1nz_root_trust_v5 as old
import tu1nz_root_trust_v51 as new

class Tests(unittest.TestCase):
    def test_exact_old_collision_reproduced(self):
        with tempfile.TemporaryDirectory() as d:
            s=old.Store(d)
            with self.assertRaisesRegex(ValueError,'output_exists'):
                s.section('docker-security',lambda:s.write('docker-security.json',b'[]'))
            self.assertEqual((Path(d)/'docker-security.json').read_bytes(),b'[]')
            self.assertEqual(s.entries[0]['status'],'OK') # Historical flaw, not reclassified.
    def test_separate_namespaces(self):
        with tempfile.TemporaryDirectory() as d:
            s=new.Store(d)
            s.section('docker-security',lambda:s.write('docker-security.json',b'[]'))
            s.section('process-identities',lambda:s.write('processes.json',b'[]'))
            s.section('expected-symlink',lambda:{'classification':'EXPECTED_SAFE_SYMLINK'})
            self.assertEqual(len(s.entries),3)
            self.assertTrue(all(x['status']=='OK' for x in s.entries))
            self.assertEqual((Path(d)/'docker-security.json').read_bytes(),b'[]')
            self.assertEqual(json.loads((Path(d)/'section-docker-security.json').read_text())['status'],'OK')
    def test_persistence_failure_not_false_ok(self):
        with tempfile.TemporaryDirectory() as d:
            s=new.Store(d);s.section('first',lambda:True)
            with patch.object(s,'write',side_effect=PermissionError('SECRET_CANARY')):s.section('later',lambda:True)
            self.assertEqual(s.entries[-1]['status'],'INCOMPLETE')
            self.assertEqual(s.entries[-1]['persistence_error_class'],'PermissionError')
            self.assertNotIn('SECRET_CANARY',str(s.entries))
            self.assertTrue((Path(d)/'section-first.json').exists())
    def test_action_failure_continues(self):
        with tempfile.TemporaryDirectory() as d:
            s=new.Store(d)
            s.section('bad',lambda:(_ for _ in ()).throw(ValueError('SECRET_CANARY')))
            s.section('next',lambda:True)
            self.assertEqual([x['status'] for x in s.entries],['INCOMPLETE','OK'])
            self.assertNotIn('SECRET_CANARY',str(s.entries))
    def test_no_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            s=new.Store(d);s.write('section-same.json',b'original');s.section('same',lambda:True)
            self.assertEqual((Path(d)/'section-same.json').read_bytes(),b'original')
            self.assertEqual(s.entries[-1]['status'],'INCOMPLETE')
    def test_interruption_keeps_first(self):
        with tempfile.TemporaryDirectory() as d:
            s=new.Store(d);s.section('first',lambda:True)
            with self.assertRaises(KeyboardInterrupt):s.section('later',lambda:(_ for _ in ()).throw(KeyboardInterrupt()))
            self.assertEqual(s.entries[-1]['status'],'INCOMPLETE')
            self.assertTrue((Path(d)/'section-first.json').exists())

class FullOrchestrationTests(unittest.TestCase):
    def run_main_fixture(self,fail=False):
        class FakeCollector:
            def __init__(self,store):self.store=store;self.nodes={};self.queue=[];self.uid=1001;self.gids={1001}
            def identities(self):return {}
            def units(self):self.store.write('unit-files.bin',b'fixture');return {}
            def docker(self):self.store.write('docker-security.json',b'[]');return {}
            def processes(self):
                if fail:raise ValueError('SECRET_CANARY')
                self.store.write('processes.json',b'[]');return {}
            def graph(self):return {'status':'INCOMPLETE','activation_ready':False}
        with tempfile.TemporaryDirectory() as d:
            output=io.StringIO()
            with patch.object(new,'BASE',Path(d)),patch.object(new,'protected_directory'),patch.object(new,'Collector',FakeCollector),patch.object(new,'ROOTS',{}),patch.object(new,'bounded_command',return_value=b''),patch.object(new,'safe_symlink',return_value={'classification':'EXPECTED_SAFE_SYMLINK'}),patch.object(new.os,'getuid',return_value=0),patch.object(new.os,'geteuid',return_value=0),patch.object(new.sys,'argv',['fixture']),patch.object(new.signal,'signal'),patch.dict(new.__dict__,{'_VERIFIED_SOURCE_SHA256':'a'*64}),patch.dict(new.os.environ,dict(new.os.environ),clear=True),contextlib.redirect_stdout(output):
                rc=new.main()
            report=json.loads(output.getvalue())
            self.assertEqual(rc,2);self.assertTrue(report['collection_finished'])
            self.assertEqual(report['status'],'INCOMPLETE')
            self.assertNotIn('SECRET_CANARY',output.getvalue())
            self.assertTrue((Path(report['directory'])/'manifest.json').is_file())
            self.assertEqual(len(report['sections']),12)
            return report
    def test_whole_sequence_after_docker(self):
        r=self.run_main_fixture()
        self.assertTrue(all(s['status']=='OK' for s in r['sections']))
    def test_later_failure_preserves_progress(self):
        r=self.run_main_fixture(True)
        self.assertEqual(next(s for s in r['sections'] if s['section']=='process-identities')['status'],'INCOMPLETE')
        self.assertEqual(r['sections'][-1]['section'],'expected-symlink')

if __name__=='__main__':unittest.main()
