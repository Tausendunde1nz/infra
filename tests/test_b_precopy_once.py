"""Fixed PRECOPY safety tests, synthetic bytes only. Retain owned temp evidence."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_b_precopy_once as c

class Once(unittest.TestCase):
    def fixture(self,seconds=10):
        root=Path(tempfile.mkdtemp(prefix='b-once-synthetic-')).resolve()
        targets=(root/'a',root/'b')
        for t in targets:t.mkdir(mode=0o700)
        at=c.Attempt(root/'attempt',time.monotonic()+seconds,targets)
        self.addCleanup(at.close)
        return root,targets,at
    def doc(self):
        return dict(schema='TU1NZ_B_PRECOPY_EXECUTION_WINDOW_V1',capture_id=c.ID,
          window_start='2026-10-20T08:00:00+00:00',window_end='2026-10-20T08:15:00+00:00',
          source_commit='a'*40,source_tree='b'*40,selection_sha256=c.SELECTION_SHA,
          schema_reference_sha256=c.REFERENCE_SHA,client_manifest_sha256=c.CLIENT_SHA,
          targets=list(map(str,c.TARGETS)),same_volume_risk_accepted=True)
    def test_exact_window_and_scope(self):
        now=datetime(2026,10,20,8,1,tzinfo=timezone.utc)
        c.approval(json.dumps(self.doc()).encode(),now)
        for key,value in [('capture_id','retry'),('source_commit','bad'),('targets',[]),
                          ('selection_sha256','f'*64),('same_volume_risk_accepted',False),
                          ('window_end','2026-10-20T09:00:00+00:00')]:
            doc=self.doc();doc[key]=value
            with self.subTest(key=key),self.assertRaises((c.m.Denied,c.b.Denied)):
                c.approval(json.dumps(doc).encode(),now)
        with self.assertRaises(c.m.Denied):
            c.approval(json.dumps(self.doc()).encode(),datetime(2026,10,21,tzinfo=timezone.utc))
    def test_one_attempt_never_replaced(self):
        root,targets,at=self.fixture()
        with self.assertRaises(FileExistsError):c.Attempt(root/'attempt',time.monotonic()+10,targets)
        self.assertIn('ATTEMPT_CONSUMED',(root/'attempt').read_text())
    def test_success_hash_copy_full_independent_read_and_tamper(self):
        _,targets,at=self.fixture()
        raw,digest,size=at.pump([sys.executable,'-I','-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],{},b'SYNTHETIC',100,targets[0]/'sample')
        self.assertEqual((digest,size),(c.m.sha(b'SYNTHETIC'),9))
        c.duplicate(at,[dict(name='sample',sha256=digest,size=size)])
        self.assertEqual((targets[1]/'sample').read_bytes(),b'SYNTHETIC')
        (targets[0]/'sample').write_bytes(b'TAMPERED!')
        with self.assertRaises(FileExistsError):c.duplicate(at,[dict(name='sample',sha256=digest,size=size)])
    def test_stream_limit_retains_partial_and_no_retry(self):
        _,targets,at=self.fixture()
        with self.assertRaisesRegex(c.m.Denied,'STREAM_LIMIT'):
            at.pump([sys.executable,'-I','-c','print("SYNTHETIC")'],{},b'',1,targets[0]/'sample')
        self.assertTrue((targets[0]/'sample').exists())
        self.assertTrue(all(p.poll() is not None for p in at.children))
    def test_deadline_including_nonreading_stdin(self):
        _,_,at=self.fixture(seconds=.15)
        with self.assertRaisesRegex(c.m.Denied,'DEADLINE'):
            at.pump([sys.executable,'-I','-c','import time;time.sleep(10)'],{},b'x'*1000000,100)
        self.assertTrue(all(p.poll() is not None for p in at.children))
    def test_reserve_and_package_limit(self):
        _,targets,at=self.fixture()
        with patch.object(c.os,'statvfs',return_value=type('V',(),dict(f_bavail=1,f_frsize=1))()):
            with self.assertRaisesRegex(c.m.Denied,'RESERVE_HOLD'):at.room()
        at.written=c.PACKAGE_CAP
        with self.assertRaisesRegex(c.m.Denied,'PACKAGE_LIMIT'):
            at.pump([sys.executable,'-I','-c','print("X")'],{},b'',100,targets[0]/'sample')
    def test_failure_no_raw_child_diagnostics(self):
        _,_,at=self.fixture()
        with self.assertRaisesRegex(c.m.Denied,'PG_TOOL_FAILED') as got:
            at.pump([sys.executable,'-I','-c','import sys;print("SYNTHETIC_PRIVATE",file=sys.stderr);sys.exit(4)'],{},b'',100)
        self.assertNotIn('PRIVATE',str(got.exception))
    def test_schema_drift_not_ignored_and_snapshot_injection(self):
        first=[dict(kind='function_meta',definition_sha256='a'*64)]
        self.assertNotEqual(c.normalized(first),c.normalized([dict(kind='function_meta',definition_sha256='b'*64)]))
        c.snapshot_sql('00000003-00000005-1','SELECT 1;')
        with self.assertRaises(c.m.Denied):c.snapshot_sql("1';COMMIT;--",'')
    def test_default_cli_inert(self):
        p=subprocess.run([sys.executable,'-I','-B','-S',str(Path(c.__file__))],capture_output=True,timeout=5)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['status'],'PLAN_ONLY_NOT_AUTHORIZED')
    def test_first_child_failure_still_removes_credential_and_no_success(self):
        at=Mock();at.children=[Mock(),Mock()]
        for p in at.children:p.poll.return_value=0
        with patch.object(c.m,'stop_owned',side_effect=[OSError('synthetic'),None]) as stop,\
             patch.object(c.m,'remove_owned_passfile') as remove,patch.object(c.os,'close'):
            with self.assertRaisesRegex(c.m.Denied,'CLEANUP_HOLD'):
                c.cleanup(at,Path('/synthetic/pgpass'),(1,2,3),None,'PRECOPY_BYTES_CHECKED_NOT_RESTORED')
        self.assertEqual(stop.call_count,2);remove.assert_called_once()
        self.assertEqual(at.event.call_args.kwargs['status'],'PARTIAL_HOLD');at.close_children.assert_called_once()
    def test_failed_credential_or_listener_cleanup_cannot_pass(self):
        for fault in ('credential','listener','deadline','journal','close'):
            at=Mock();at.children=[]
            if fault=='deadline':at.left.side_effect=c.m.Denied('DEADLINE')
            if fault=='journal':at.event.side_effect=OSError('synthetic')
            if fault=='close':at.close_children.side_effect=OSError('synthetic')
            with patch.object(c.m,'remove_owned_passfile',side_effect=OSError('synthetic') if fault=='credential' else None) as remove,\
                 patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'unexpected listener',b'')),patch.object(c.os,'close'):
                with self.subTest(fault=fault),self.assertRaisesRegex(c.m.Denied,'CLEANUP_HOLD'):
                    c.cleanup(at,None,None,object() if fault=='listener' else None,'PRECOPY_BYTES_CHECKED_NOT_RESTORED')
            remove.assert_called_once();at.close_children.assert_called_once()
            if fault!='journal':self.assertEqual(at.event.call_args.kwargs['status'],'PARTIAL_HOLD')
if __name__=='__main__':unittest.main()
