"""Fixed PRECOPY safety tests, synthetic bytes only. Retain owned temp evidence."""
from datetime import datetime, timezone
from copy import deepcopy
import io
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

def settings():
    return [dict(kind='safe_setting_meta',name=name,value='off' if name=='jit' else '',
                 source='default') for name in sorted(c.SETTING_NAMES)]

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
        first=settings()+[dict(kind='function_meta',definition_sha256='a'*64)]
        self.assertNotEqual(c.normalized(first),c.normalized(settings()+[dict(kind='function_meta',definition_sha256='b'*64)]))
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

    def test_every_captured_setting_and_its_source_participate_in_comparison(self):
        reference=settings()
        self.assertEqual(c.normalized(reference),c.normalized(list(reversed(reference))))
        for name in c.SETTING_NAMES:
            for field in ('value','source'):
                changed=deepcopy(reference)
                next(r for r in changed if r['name']==name)[field]='synthetic_changed'
                with self.subTest(name=name,field=field):
                    self.assertNotEqual(c.normalized(reference),c.normalized(changed))

    def test_missing_malformed_duplicate_or_unexpected_settings_cannot_pass(self):
        reference=settings()
        for name in c.SETTING_NAMES:
            missing=[r for r in reference if r['name']!=name]
            with self.subTest(name=name):
                if name in c.UNKNOWN_SETTINGS:
                    self.assertNotEqual(c.normalized(reference),c.normalized(missing))
                else:
                    with self.assertRaisesRegex(c.m.Denied,'REQUIRED_SETTING_MISSING'):
                        c.normalized(missing)
            for field in ('value','source'):
                for replacement in ('missing',None,False):
                    broken=deepcopy(reference);row=next(r for r in broken if r['name']==name)
                    if replacement=='missing':del row[field]
                    else:row[field]=replacement
                    with self.subTest(name=name,field=field,replacement=replacement),self.assertRaises(c.m.Denied):
                        c.normalized(broken)
        for broken in (reference+[reference[0]],reference+[dict(kind='safe_setting_meta',name='unbound',value='',source='default')],[]):
            with self.assertRaises(c.m.Denied):c.normalized(broken)

    def test_only_bound_unknown_visibility_is_preserved_without_empty_value_claim(self):
        visible=[r for r in settings() if r['name'] not in c.UNKNOWN_SETTINGS]
        result=c.setting_observations(visible)
        unknown=[r for r in result if r.get('observation')=='UNKNOWN_NOT_VISIBLE']
        self.assertEqual({r['name'] for r in unknown},c.UNKNOWN_SETTINGS)
        self.assertTrue(all('value' not in r and 'source' not in r for r in unknown))
        self.assertEqual(c.normalized(visible),c.normalized(deepcopy(visible)))
        # Revealing a formerly hidden setting is a visibility change, not an
        # automatically approved replacement for the pinned unknown state.
        self.assertNotEqual(c.normalized(visible),c.normalized(settings()))

    def test_setting_drift_holds_before_inside_and_after_snapshot(self):
        identity=dict(kind='identity',database='synthetic',role='synthetic',session_role='synthetic',
                      version='170011',postmaster_start='synthetic',ssl=True)
        reference=[identity,*settings()]
        owner=dict(identity,read_only='on')
        for phase,code in ((0,'PREFLIGHT_SCHEMA_OR_RIGHTS_DRIFT'),(1,'SCHEMA_OR_RIGHTS_DRIFT'),(2,'FINAL_SCHEMA_OR_HOLDER_DRIFT')):
            for name in c.SETTING_NAMES:
                with self.subTest(phase=phase,name=name):
                    _,_,at=self.fixture()
                    snapshots=[deepcopy(reference) for _ in range(3)]
                    next(r for r in snapshots[phase] if r.get('name')==name)['value']='synthetic_changed'
                    encoded=[b'\n'.join(json.dumps(r).encode() for r in rows)+b'\n' for rows in snapshots]
                    at.pump=Mock(side_effect=[(encoded[0],'',0),(encoded[1],'',0),(b'','a'*64,1),(b'','b'*64,1),(encoded[2],'',0)])
                    reader,writer=os.pipe();os.write(writer,json.dumps(owner).encode()+b'\n00000003-00000005-1\n');os.close(writer)
                    stream=os.fdopen(reader,'rb');self.addCleanup(stream.close)
                    keeper=Mock(stdin=io.BytesIO(),stdout=stream,returncode=0);keeper.poll.return_value=None
                    at.spawn=Mock(return_value=keeper)
                    with patch.object(c,'table_fingerprint',return_value={}),patch.object(c.b,'dump_argv',return_value=['synthetic']):
                        with self.assertRaisesRegex(c.m.Denied,code):
                            c.capture(at,Path('/synthetic'),{},[],reference,{},'a'*64,validate=lambda *_:None)
                    self.assertEqual(at.pump.call_count,(1,2,5)[phase])


class Durability(unittest.TestCase):
    def root(self):
        return Path(tempfile.mkdtemp(prefix='b-durability-synthetic-')).resolve()

    def recorder(self,fail=None):
        original_open,original_sync=os.open,os.fsync
        labels={};events=[]
        def opened(path,flags,*args):
            fd=original_open(path,flags,*args);labels[fd]=Path(path)
            events.append(('open',Path(path),flags));return fd
        def synced(fd):
            path=labels[fd];events.append(('fsync',path))
            if path==fail:raise OSError('synthetic fsync failure')
            original_sync(fd)
        return opened,synced,events,labels

    def test_binding_files_then_each_parent_before_successful_finish(self):
        for separate in (False,True):
            root=self.root();stage=root/'stage';stage.mkdir(mode=0o700)
            other=root/'other';other.mkdir(mode=0o700)
            receipt=stage/'receipt';manifest=(other if separate else stage)/'manifest'
            at=Mock(children=[],fd=-1)
            opened,synced,events,_=self.recorder()
            with patch.object(c.os,'open',side_effect=opened),patch.object(c.os,'fsync',side_effect=synced):
                c.persist_bindings(at,receipt,b'SYNTHETIC',manifest,b'SYNTHETIC')
            at.event.side_effect=lambda name,**kw:events.append((name,kw['status']))
            with patch.object(c.m,'remove_owned_passfile'),patch.object(c.os,'close'):
                c.cleanup(at,None,None,None,'PRECOPY_BYTES_CHECKED_NOT_RESTORED')
            self.assertEqual([e[1] for e in events if e[0]=='fsync'],[receipt,manifest,stage]+([other] if separate else []))
            self.assertEqual(events[-1],('FINISH','PRECOPY_BYTES_CHECKED_NOT_RESTORED'))
            for event in events:
                if event[0]=='open' and event[1] in (stage,other):
                    self.assertTrue(event[2]&os.O_DIRECTORY and event[2]&os.O_NOFOLLOW)

    def test_file_or_parent_sync_failure_never_finishes_successfully(self):
        for failed in ('receipt','manifest','first_parent','second_parent'):
            root=self.root();a=root/'a';b=root/'b';a.mkdir(mode=0o700);b.mkdir(mode=0o700)
            receipt=a/'receipt';manifest=b/'manifest'
            fail={'receipt':receipt,'manifest':manifest,'first_parent':a,'second_parent':b}[failed]
            at=Mock(children=[],fd=-1);opened,synced,_,labels=self.recorder(fail)
            status='PARTIAL_HOLD'
            with patch.object(c.os,'open',side_effect=opened),patch.object(c.os,'fsync',side_effect=synced):
                with self.assertRaises(OSError):
                    try:
                        c.persist_bindings(at,receipt,b'SYNTHETIC',manifest,b'SYNTHETIC')
                        status='PRECOPY_BYTES_CHECKED_NOT_RESTORED'
                    finally:
                        with patch.object(c.m,'remove_owned_passfile'),patch.object(c.os,'close'):
                            c.cleanup(at,None,None,None,status)
            self.assertEqual(at.event.call_args.kwargs['status'],'PARTIAL_HOLD')
            # All binding/parent descriptors were closed even on fsync error.
            for fd in labels:
                with self.assertRaises(OSError):os.fstat(fd)
            self.assertTrue(receipt.exists())  # owned partials are retained

    def test_payload_directories_and_new_names_in_both_parents_are_synced(self):
        for fail_index in (None,0,1,2,3):
            root=self.root();parents=(root/'a',root/'b')
            for p in parents:p.mkdir(mode=0o700)
            targets=tuple(p/'capture' for p in parents)
            for p in targets:p.mkdir(mode=0o700)
            (targets[0]/'sample').write_bytes(b'SYNTHETIC')
            at=c.Attempt(root/'attempt',time.monotonic()+10,targets)
            self.addCleanup(at.close)
            directories=(*targets,*parents)
            opened,synced,events,_=self.recorder(None if fail_index is None else directories[fail_index])
            with patch.object(c.os,'open',side_effect=opened),patch.object(c.os,'fsync',side_effect=synced):
                if fail_index is None:c.duplicate(at,[dict(name='sample',size=9,sha256=c.m.sha(b'SYNTHETIC'))])
                else:
                    with self.assertRaises(OSError):c.duplicate(at,[dict(name='sample',size=9,sha256=c.m.sha(b'SYNTHETIC'))])
            syncs=[e[1] for e in events if e[0]=='fsync']
            self.assertEqual(syncs,[targets[1]/'sample',*directories[:4 if fail_index is None else fail_index+1]])

if __name__=='__main__':unittest.main()
