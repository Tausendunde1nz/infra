"""S7 supplement synthetic boundaries: no production paths, data or access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
from tests import test_mainserver_restore as fixtures

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
s=load('tu1nz_mainserver_s7_supplement');e=load('tu1nz_mainserver_s7_file_restore')
c=load('tu1nz_mainserver_db_completion');b=load('tu1nz_mainserver_backup');r=load('tu1nz_mainserver_restore')


class EntryCustody(unittest.TestCase):
    def test_import_inert_wrong_identity_denied_before_operational_read(self):
        with patch.object(s.os,'getuid',return_value=123),patch.object(s,'validate_inputs',side_effect=AssertionError):
            with self.assertRaisesRegex(s.Denied,'MAC_DANIEL_REQUIRED'):s.capture_main()
        with patch.object(e.os,'getuid',return_value=123),patch.object(e,'read',side_effect=AssertionError):
            with self.assertRaisesRegex(e.Denied,'PERSONAL_MAC_ROOT'):e.main()
        for name in s.MODULES:self.assertIsNotNone(s.load(name,(SCRIPTS/name).read_bytes()))
    def test_begin_creates_unique_directory_and_attempt_and_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(s,'PARENT',Path(temp).resolve()),patch.object(s,'directory',return_value=(1,2)):
            with patch.object(s,'OUTPUT',s.PARENT/'supplement'):
                s.begin(r,'2'*64,'3'*64,{'original_sha256':{'files.json':'1'*64}})
                raw=(s.OUTPUT/'ATTEMPT.json').read_bytes();a=json.loads(raw)
                self.assertEqual((a['SSH_max'],a['DB_sessions_max'],a['concurrent_DB_max']),(1,8,2))
                self.assertFalse(a['retry_allowed']);self.assertEqual(a['e1_hold_sha256'],s.E1_RESULT)
                with self.assertRaisesRegex(s.Denied,'OCCUPIED'):s.begin(r,'2'*64,'3'*64,{})
                self.assertEqual((s.OUTPUT/'ATTEMPT.json').read_bytes(),raw)
    def test_empty_or_foreign_output_already_consumes_local_entry(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(s,'PARENT',Path(temp).resolve()),patch.object(s,'directory',return_value=(1,2)):
            with patch.object(s,'OUTPUT',s.PARENT/'supplement'):
                s.OUTPUT.mkdir()
                with self.assertRaisesRegex(s.Denied,'OCCUPIED'):s.begin(r,'2'*64,'3'*64,{})
    def test_read_requires_original_owner_mode_single_link_and_stable_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();p=root/'object';p.write_bytes(b'SYNTHETIC');p.chmod(0o600)
            self.assertEqual(s.read(p,20,os.geteuid()),b'SYNTHETIC')
            alias=root/'alias';alias.symlink_to(p)
            with self.assertRaisesRegex(s.Denied,'CANONICAL'):s.read(alias,20,os.geteuid())
            p.chmod(0o640)
            with self.assertRaisesRegex(s.Denied,'PROFILE'):s.read(p,20,os.geteuid())
            p.chmod(0o600);link=root/'link';os.link(p,link)
            with self.assertRaisesRegex(s.Denied,'PROFILE'):s.read(p,20,os.geteuid())
            link.unlink();real=os.read
            def drift(fd,n):
                raw=real(fd,n)
                if raw:os.utime(p,ns=(1,2))
                return raw
            with patch.object(s.os,'read',side_effect=drift),self.assertRaisesRegex(s.Denied,'CHANGED'):s.read(p,20,os.geteuid())
    def test_extra_parent_object_denies_before_any_original_payload_read(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(s,'PARENT',Path(temp).resolve()),patch.object(s,'directory',return_value=()):
            with patch.object(s.os,'listdir',return_value=['foreign']),patch.object(s,'read',side_effect=AssertionError):
                with self.assertRaisesRegex(s.Denied,'FOREIGN_OR_OCCUPIED'):s.prior_files({'e1_extra_sha256':{}},c,b,None,{},supplement_exists=False)


class SessionBudget(unittest.TestCase):
    def budget(self):
        inner=Mock();inner.token='BOUND';receipt={};budget=s.SnapshotBudget(inner,r.TABLES,receipt)
        budget.start(database=b.DATABASE,role=b.ROLE);return inner,receipt,budget
    def test_exact_eight_sessions_max_two_same_snapshot_and_no_ninth(self):
        inner,receipt,x=self.budget();x.read('catalog');x.read('rights')
        for name in r.TABLES:x.read('fingerprint',{},name)
        x.dump()
        for name in r.TABLES:x.read('fingerprint',{},name)
        self.assertEqual(receipt,{'attempted':8,'max_simultaneous':2})
        with self.assertRaises(s.Denied):x.dump()
        inner.dump.assert_called_once()
    def test_wrong_order_concurrent_worker_and_new_snapshot_denied_before_new_session(self):
        for mode in ('order','concurrent','token'):
            inner,receipt,x=self.budget()
            if mode=='concurrent':x.worker=True
            if mode=='token':inner.token='CHANGED'
            with self.subTest(mode=mode),self.assertRaises(s.Denied):x.read('rights' if mode=='order' else 'catalog')
            inner.read.assert_not_called();self.assertEqual(receipt['attempted'],1)
    def test_failed_session_consumes_its_slot_and_is_not_repeated(self):
        inner,receipt,x=self.budget();inner.read.side_effect=RuntimeError('synthetic')
        with self.assertRaises(RuntimeError):x.read('catalog')
        with self.assertRaises(s.Denied):x.read('catalog')
        inner.read.assert_called_once();self.assertEqual(receipt['attempted'],2)


class Transport(unittest.TestCase):
    def spawn(self,code='import time;time.sleep(30)',deadline=5,listener=None):
        real=subprocess.Popen;self.children=[];self.argv=[];self.receipt={}
        def launch(argv,**kw):
            self.argv.append(argv);p=real([sys.executable,'-I','-B','-c',code],**kw);self.children.append(p);return p
        def lsof(argv,**kw):
            self.assertEqual(argv[:4],['/usr/sbin/lsof','-nP','-a','-p'])
            return listener if listener is not None else (0,('p'+str(self.children[-1].pid)+'\nf3\nn127.0.0.1:15432\n').encode(),b'')
        with patch.object(s.subprocess,'Popen',side_effect=launch),patch.object(r,'bounded_process',side_effect=lsof):
            return s.ObservedTunnel(b,r,time.monotonic()+deadline,self.receipt)
    def test_one_fixed_forward_no_remote_program_and_normal_own_child_cleanup(self):
        tunnel=self.spawn()
        try:
            self.assertEqual(self.argv[0][:5],['/usr/bin/ssh','-F','/dev/null','-T','-N'])
            self.assertEqual(self.argv[0][-3:],['-L','127.0.0.1:15432:127.0.0.1:5432','100.121.130.51'])
            self.assertNotIn('sudo',' '.join(self.argv[0]));self.assertEqual(self.argv[0].count('-L'),1)
            with patch.object(s,'port_free'):proof=tunnel.finish()
            self.assertTrue(proof['own_ssh_ended']);self.assertFalse(proof['remote_process_cleanup_observed'])
            self.assertEqual(self.receipt['launches'],1);self.assertTrue(self.receipt['normal_close_after_rollback'])
            self.assertTrue(self.receipt['own_child_ended']);self.assertEqual(self.receipt['stderr_private'],'')
        finally:tunnel.abort()
    def test_constructor_failure_retains_bounded_private_error_and_status(self):
        code='import sys;sys.stderr.write("SYNTHETIC_TRANSPORT_FAILURE\\n");sys.stderr.flush();sys.exit(42)'
        with self.assertRaises(s.Denied):self.spawn(code,listener=(1,b'',b''))
        self.assertEqual(self.receipt['child_status'],42);self.assertEqual(self.receipt['status_before_cleanup'],42)
        self.assertIn('SYNTHETIC_TRANSPORT_FAILURE',self.receipt['stderr_private'])
        self.assertEqual(self.receipt['phase'],'WAIT_FIXED_LISTENER');self.assertFalse(self.receipt['deadline_expired'])
        self.assertEqual(len(self.children),1);self.assertTrue(self.receipt['own_child_ended'])
    def test_bounded_diagnostic_overflow_denies_and_kills_only_own_child(self):
        with self.assertRaises(s.Denied):self.spawn('import sys,time;sys.stderr.write("X"*20000);sys.stderr.flush();time.sleep(30)',listener=(1,b'',b''))
        self.assertLessEqual(len(self.receipt['stderr_private']),4096);self.assertTrue(self.receipt['truncated'])
        self.assertTrue(self.receipt['own_child_ended']);self.assertEqual(len(self.children),1)
    def test_deadline_and_listener_mismatch_preserve_failure_phase(self):
        with self.assertRaises(s.Denied):self.spawn(deadline=.07,listener=(1,b'',b''))
        self.assertTrue(self.receipt['deadline_expired']);self.assertTrue(self.receipt['readiness_deadline_expired'])
        self.assertEqual(self.receipt['phase'],'WAIT_FIXED_LISTENER');self.assertIsNotNone(self.children[0].poll())
        with self.assertRaisesRegex(s.Denied,'LISTENER_MISMATCH'):self.spawn(listener=(0,b'p1\nf3\nn0.0.0.0:15432\n',b''))
        self.assertTrue(self.receipt['own_child_ended'])
    def test_spawn_failure_is_single_attempt_and_diagnostic_survives(self):
        receipt={}
        with patch.object(s.subprocess,'Popen',side_effect=OSError('synthetic')) as spawn:
            with self.assertRaises(OSError):s.ObservedTunnel(b,r,time.monotonic()+5,receipt)
        spawn.assert_called_once();self.assertEqual(receipt['launches'],1);self.assertEqual(receipt['phase'],'SPAWN')
        self.assertTrue(receipt['own_child_ended']);self.assertIsNone(receipt['child_status'])


class Flow(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.patch=patch.object(s,'OUTPUT',self.root);self.patch.start();self.original_read=s.read
        self.reader=patch.object(s,'read',side_effect=lambda p,n:self.original_read(p,n,os.geteuid()));self.reader.start()
        cat=fixtures.CatalogBoundary();self.rows=cat.rows();self.cat=cat.raw(self.rows);self.local_cat=self.cat
        self.rights=b'{"kind":"runtime_role","name":"SYNTHETIC","superuser":false}\n';self.local_rights=self.rights
        self.data=b'{"id":"SYNTHETIC"}\n';self.render=fixtures.DumpBoundary().render(b'1\n').replace(b'(id, payload)',b'(id)')
        self.calls=[];self.receipt={};owner=self
        class Snapshot:
            def __init__(self,*a,**kw):self.token=None;self.child=None;owner.calls.append('snapshot')
            def start(self,**kw):
                self.token='SYNTHETIC';self.child=object()
                return {'database':b.DATABASE,'role':b.ROLE,'session_role':b.ROLE,'readonly':'on','version':'170011','snapshot':self.token}
            def read(self,kind,*a):owner.calls.append(kind);return {'catalog':owner.cat,'rights':owner.rights,'fingerprint':owner.data}[kind]
            def dump(self):owner.calls.append('dump');return b'PGDMPSYNTHETIC'
            def close(self):owner.calls.append('rollback')
        class Tunnel:
            def __init__(self,*a):
                owner.calls.append('tunnel');self.d=a[-1];self.d.update(launches=1,truncated=False,stdout_private='',stderr_private='')
            def live(self):owner.calls.append('live')
            def finish(self):
                owner.calls.append('finish');self.d.update(normal_close_after_rollback=True,own_child_ended=True)
                return {'own_ssh_ended':True,'local_forward_removed':True,'remote_program_executed':False,'remote_process_cleanup_observed':False}
            def abort(self):owner.calls.append('abort')
        self.Snapshot=Snapshot;self.Tunnel=Tunnel
        self.pg=Mock();self.pg.call.side_effect=lambda *a,**kw:(0,self.render,b'')
        self.pg.query.side_effect=lambda sql:self.cat if sql==r.catalog_transaction() else self.rights if sql==r.rights_transaction() else self.data
    def tearDown(self):self.reader.stop();self.patch.stop();self.temp.cleanup()
    def flow(self):return s.capture_and_restore(r,b,self.pg,Path('/synthetic'),self.local_cat,self.local_rights,self.receipt,tunnel_factory=self.Tunnel,snapshot_factory=self.Snapshot)
    def test_eight_session_real_flow_order_full_restore_and_known_rollback(self):
        self.flow();self.assertEqual(self.receipt['source_sessions'],{'attempted':8,'max_simultaneous':2})
        self.assertEqual(self.calls.count('tunnel'),1);self.assertEqual(self.calls.count('dump'),1)
        self.assertLess(self.calls.index('rollback'),self.calls.index('finish'));self.assertTrue(self.receipt['snapshot_rollback_acknowledged'])
        self.assertEqual(self.receipt['snapshot']['fingerprints'],self.receipt['restored_fingerprints']);self.pg.restore_copies.assert_called_once()
    def test_unknown_owner_or_rights_stops_before_business_data_dump(self):
        for kind in ('owner','rights'):
            with self.subTest(kind=kind):
                if kind=='owner':
                    rows=copy.deepcopy(self.rows);rows[0]['owner']='UNKNOWN';self.cat=fixtures.CatalogBoundary().raw(rows)
                else:self.cat=self.local_cat;self.rights=self.rights.replace(b'false',b'true')
                with self.assertRaises(r.Denied):self.flow()
                self.assertNotIn('dump',self.calls);self.assertNotIn('fingerprint',self.calls);self.pg.restore_copies.assert_not_called()
                for name in ('source-catalog.jsonl','source-rights.jsonl'):(self.root/name).unlink()
    def test_snapshot_start_without_process_cannot_invent_rollback_ack(self):
        def failure(instance,**kw):raise r.Denied('SYNTHETIC_NO_PROCESS')
        self.Snapshot.start=failure
        with self.assertRaises(r.Denied):self.flow()
        self.assertEqual(self.receipt['source_snapshot_cleanup'],'NOT_STARTED');self.assertNotIn('snapshot_rollback_acknowledged',self.receipt)
        self.assertEqual(self.calls.count('abort'),1);self.pg.restore_copies.assert_not_called()
    def test_unknown_rollback_is_not_retried_or_called_success(self):
        def lost(instance):self.calls.append('rollback');raise r.Denied('SYNTHETIC_UNKNOWN_ACK')
        self.Snapshot.close=lost
        with self.assertRaisesRegex(r.Denied,'UNKNOWN_ACK'):self.flow()
        self.assertEqual(self.calls.count('rollback'),1);self.assertEqual(self.calls.count('abort'),1)
        self.assertEqual(self.receipt['source_snapshot_cleanup'],'UNCONFIRMED');self.assertNotIn('snapshot_rollback_acknowledged',self.receipt)
        self.pg.restore_copies.assert_not_called()
    def test_transport_failure_before_dump_never_reconnects(self):
        self.Tunnel.live=lambda instance:(_ for _ in ()).throw(s.Denied('SYNTHETIC_CHANNEL_LOST'))
        with self.assertRaises(s.Denied):self.flow()
        self.assertEqual(self.calls.count('tunnel'),1);self.assertNotIn('dump',self.calls);self.assertEqual(self.calls.count('rollback'),1)
    def test_partial_archive_or_executable_sql_not_imported(self):
        self.render=b'COPY public.commercial_s7_waitlist (id) FROM stdin;\nPARTIAL'
        with self.assertRaises(r.Denied):self.flow()
        self.pg.restore_copies.assert_not_called();self.assertTrue(self.receipt['snapshot_rollback_acknowledged'])
    def test_changed_source_fingerprint_cannot_be_accepted(self):
        original=self.Snapshot.read;count=0
        def changed(instance,kind,*args):
            nonlocal count
            raw=original(instance,kind,*args)
            if kind=='fingerprint':
                count+=1
                if count>2:return b'DIFFERENT\n'
            return raw
        self.Snapshot.read=changed
        with self.assertRaisesRegex(s.Denied,'SNAPSHOT_DRIFT'):self.flow()
        self.pg.restore_copies.assert_not_called()
    def test_new_file_admission_requires_all_real_db_gates_and_full_readback(self):
        self.flow();old={'original_sha256':{'files.json':'1'*64}}
        diagnostic=s.canonical(self.receipt.pop('transport_diagnostic'));r.private_create(self.root/'transport.json',diagnostic)
        result={**self.receipt,'schema':'TU1NZ_S7_SUPPLEMENT_RESULT_V1','status':s.PASS,'cleanup':[],
            'scope_sha256':'2'*64,'review_sha256':'3'*64,'e1_hold_sha256':s.E1_RESULT,'original_remote_closed_ACK_received':False,
            'host_mutations':False,'production_restore':False,'private_restore_cleanup':{'own_cluster_removed':True,'own_socket_removed':True},
            'transport_diagnostic_sha256':s.sha(diagnostic)}
        attempt={'schema':'TU1NZ_S7_SUPPLEMENT_ATTEMPT_V1','transaction':s.TX,'approval_sha256':s.APPROVAL,
            'scope_sha256':'2'*64,'review_sha256':'3'*64,'e1_attempt_sha256':s.E1_ATTEMPT,'e1_hold_sha256':s.E1_RESULT,
            'retry_allowed':False,'file_manifest_sha256':'1'*64,'SSH_max':1,'DB_sessions_max':8,'concurrent_DB_max':2}
        r.private_create(self.root/'ATTEMPT.json',s.canonical(attempt));r.private_create(self.root/'restore-server.log',b'SYNTHETIC')
        p=self.root/'RESULT.json';r.private_create(p,s.canonical(result))
        with patch.object(s,'directory'),patch.object(s,'SOCKET',self.root/'absent-socket'):
            s.checked_db_receipt({},'2'*64,'3'*64,r,old)
            for key,value in (('status','HOLD'),('snapshot_rollback_acknowledged',False),('cleanup',['UNKNOWN']),
                              ('original_remote_closed_ACK_received',True),('capture_seconds',300),('restore_seconds',300),
                              ('source_sessions',{'attempted':9,'max_simultaneous':2}),('e1_hold_sha256','0'*64)):
                p.write_bytes(s.canonical({**result,key:value}))
                with self.subTest(key=key),self.assertRaises(s.Denied):s.checked_db_receipt({},'2'*64,'3'*64,r,old)
            p.write_bytes(s.canonical(result));(self.root/'s7.dump').write_bytes(b'PGDMPCORRUPT')
            with self.assertRaisesRegex(s.Denied,'FULL_READBACK'):s.checked_db_receipt({},'2'*64,'3'*64,r,old)


@unittest.skipUnless(os.geteuid()==0,'root output ownership checked by Linux synthetic CI')
class RootOutput(unittest.TestCase):
    def test_only_additive_private_user_owned_receipts(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(e,'OUTPUT',Path(temp).resolve()):
            fd=os.open(e.OUTPUT,os.O_RDONLY|os.O_DIRECTORY)
            try:
                e.write_receipt(fd,'FILE_RESTORE_RESULT.json',b'{"synthetic":true}')
                st=(e.OUTPUT/'FILE_RESTORE_RESULT.json').stat()
                self.assertEqual((st.st_uid,st.st_gid,st.st_mode&0o777),(501,20,0o600))
                with self.assertRaises(FileExistsError):e.write_receipt(fd,'FILE_RESTORE_RESULT.json',b'changed')
                with self.assertRaises(e.Denied):e.write_receipt(fd,'RESULT.json',b'changed')
            finally:os.close(fd)


if __name__=='__main__':unittest.main()
