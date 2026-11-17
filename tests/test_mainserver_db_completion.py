"""E1 adversarial synthetic orchestration; never real paths, secrets or Host."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
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
c=load('tu1nz_mainserver_db_completion');b=load('tu1nz_mainserver_backup');r=load('tu1nz_mainserver_restore')
e=load('tu1nz_mainserver_db_file_restore')


class EntryAndCustody(unittest.TestCase):
    def test_import_inert_and_entry_rejects_no_personal_terminal(self):
        with patch.object(c,'validate_inputs',side_effect=AssertionError('must not read operational inputs')):
            with self.assertRaisesRegex(c.Denied,'PERSONAL_MAC_TTY'):c.capture_main()
        for name in c.MODULES:self.assertIsNotNone(c.load(name,(SCRIPTS/name).read_bytes()))
    def test_exclusive_marker_consumed_even_without_a_result(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(c,'OUTPUT',Path(temp).resolve()):
            c.OUTPUT.chmod(0o700);scope={'original_sha256':{'files.json':'1'*64}}
            c.begin(r,'2'*64,'3'*64,scope);before=(c.OUTPUT/'DB_COMPLETION_ATTEMPT.json').read_bytes()
            with self.assertRaises(FileExistsError):c.begin(r,'2'*64,'3'*64,scope)
            self.assertEqual((c.OUTPUT/'DB_COMPLETION_ATTEMPT.json').read_bytes(),before)
            receipt=json.loads(before);self.assertFalse(receipt['retry_allowed']);self.assertFalse(receipt['original_remote_closed_ACK_received'])
            self.assertEqual(receipt['original_hold_sha256'],c.OLD_RESULT)
    def test_partial_marker_foreign_entry_or_second_run_fails_before_any_original_read(self):
        for extra in ('DB_COMPLETION_ATTEMPT.json','PROTECTION_COMPLETION.json','foreign'):
            with self.subTest(extra=extra),tempfile.TemporaryDirectory() as temp,patch.object(c,'OUTPUT',Path(temp).resolve()):
                root=c.OUTPUT;root.chmod(0o700);(root/'blobs').mkdir(mode=0o700)
                for n in c.ORIGINAL:
                    if n!='blobs':(root/n).write_bytes(b'SYNTHETIC')
                (root/extra).write_bytes(b'')
                with patch.object(c,'directory',return_value=()),patch.object(c,'read',side_effect=AssertionError('must not read originals')):
                    with self.assertRaisesRegex(c.Denied,'OCCUPIED'):c.prior_files({},b,None,phase='capture')
    def test_private_metadata_symlink_hardlink_and_wrong_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();p=root/'object';p.write_bytes(b'SYNTHETIC');p.chmod(0o600)
            self.assertEqual(c.read(p,20,os.geteuid()),b'SYNTHETIC')
            link=root/'link';os.link(p,link)
            with self.assertRaisesRegex(c.Denied,'PROFILE'):c.read(p,20,os.geteuid())
            link.unlink();p.chmod(0o640)
            with self.assertRaisesRegex(c.Denied,'PROFILE'):c.read(p,20,os.geteuid())
            alias=root/'alias';alias.symlink_to(p)
            with self.assertRaisesRegex(c.Denied,'CANONICAL'):c.read(alias,20,os.geteuid())
    def test_credential_environment_reuses_closed_parser_and_separate_private_path(self):
        env=c.environment(b,Path('/synthetic/tools'))
        self.assertTrue(env['PGPASSFILE'].endswith('/db-completion-transient.pgpass'))
        self.assertEqual(env['PGSSLMODE'],'require');self.assertEqual(env['PGCHANNELBINDING'],'require')
        self.assertFalse({'PGPASSWORD','HOME','LD_PRELOAD','DYLD_INSERT_LIBRARIES'}&set(env))
    def test_root_entry_denies_incorrect_platform_or_identity_without_data_access(self):
        with patch.object(e,'read',side_effect=AssertionError('must not read backup')):
            with self.assertRaisesRegex(e.Denied,'PERSONAL_MAC_ROOT'):e.main()


class TunnelBoundary(unittest.TestCase):
    def spawn(self,code,deadline=5,listener=None):
        real=subprocess.Popen;self.children=[];self.argv=[]
        def launch(argv,**kw):
            self.argv.append(argv);child=real([sys.executable,'-I','-B','-c',code],**kw);self.children.append(child);return child
        def lsof(argv,**kw):
            self.assertEqual(argv[:4],['/usr/sbin/lsof','-nP','-a','-p'])
            self.assertIn('-iTCP@127.0.0.1:15432',argv)
            return listener if listener is not None else (0,('p'+str(self.children[-1].pid)+'\nf3\nn127.0.0.1:15432\n').encode(),b'')
        with patch.object(c.subprocess,'Popen',side_effect=launch),patch.object(r,'bounded_process',side_effect=lsof):
            return c.Tunnel(b,r,time.monotonic()+deadline)
    def test_only_single_fixed_tunnel_no_remote_command_or_sudo(self):
        tunnel=self.spawn('import time;time.sleep(30)')
        try:
            argv=self.argv[0];self.assertEqual(argv[:5],['/usr/bin/ssh','-F','/dev/null','-T','-N'])
            self.assertEqual(argv[-3:],['-L','127.0.0.1:15432:127.0.0.1:5432','100.121.130.51'])
            self.assertEqual(argv.count('-L'),1);self.assertNotIn('sudo',' '.join(argv))
            with patch.object(c,'port_free') as free:result=tunnel.finish();free.assert_called_once()
            self.assertTrue(result['own_ssh_ended']);self.assertFalse(result['remote_process_cleanup_observed'])
            self.assertEqual(len(self.children),1)
        finally:tunnel.abort()
    def test_wrong_listener_denied_and_own_child_closed(self):
        with self.assertRaisesRegex(c.Denied,'LISTENER_MISMATCH'):
            self.spawn('import time;time.sleep(30)',listener=(0,b'p1\nn0.0.0.0:15432\n',b''))
        self.assertIsNotNone(self.children[0].poll())
    def test_channel_diagnostic_loss_or_deadline_never_reconnects(self):
        for mode in ('diagnostic','lost','deadline'):
            with self.subTest(mode=mode):
                tunnel=self.spawn('import time;time.sleep(30)')
                try:
                    if mode=='deadline':tunnel.deadline=time.monotonic()-1
                    elif mode=='lost':tunnel.child.kill();tunnel.child.wait()
                    else:
                        # Existing pipe EOF is also an unknown channel state.
                        tunnel.child.terminate();tunnel.child.wait()
                    with self.assertRaises(c.Denied):tunnel.live()
                    self.assertEqual(len(self.children),1)
                finally:tunnel.abort()
    def test_no_ready_listener_has_no_unbounded_wait(self):
        with self.assertRaises(c.Denied):self.spawn('import time;time.sleep(30)',deadline=.08,listener=(1,b'',b''))
        self.assertIsNotNone(self.children[0].poll())


class Orchestration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.patch=patch.object(c,'OUTPUT',self.root);self.patch.start()
        self.original_read=c.read
        self.reader=patch.object(c,'read',side_effect=lambda p,n:self.original_read(p,n,os.geteuid()));self.reader.start()
        catalog=fixtures.CatalogBoundary();self.rows=catalog.rows();self.cat=catalog.raw(self.rows)
        self.rights=b'{"kind":"runtime_role","name":"SYNTHETIC","superuser":false}\n'
        self.data=b'{"id":"SYNTHETIC"}\n';self.render=fixtures.DumpBoundary().render(b'1\n').replace(b'(id, payload)',b'(id)')
        self.calls=[];owner=self
        class Snapshot:
            def __init__(self,*a,**kw):owner.calls.append('snapshot');self.deadline=kw['deadline']
            def start(self,**kw):return {'database':b.DATABASE,'role':b.ROLE,'session_role':b.ROLE,'readonly':'on','version':'170011','snapshot':'SYNTHETIC'}
            def read(self,kind,*args):
                owner.calls.append(kind)
                return {'catalog':owner.cat,'rights':owner.rights,'fingerprint':owner.data}[kind]
            def dump(self):owner.calls.append('dump');return b'PGDMPSYNTHETIC'
            def close(self):owner.calls.append('rollback')
        class Tunnel:
            def __init__(self,*a):owner.calls.append('tunnel')
            def live(self):owner.calls.append('live')
            def finish(self):owner.calls.append('finish');return {'own_ssh_ended':True,'local_forward_removed':True,'remote_program_executed':False,'remote_process_cleanup_observed':False}
            def abort(self):owner.calls.append('abort')
        self.Snapshot=Snapshot;self.Tunnel=Tunnel
        self.pg=Mock();self.pg.call.side_effect=lambda *a,**kw:(0,self.render,b'')
        self.pg.query.side_effect=lambda sql:self.cat if sql==r.catalog_transaction() else self.rights if sql==r.rights_transaction() else self.data
    def tearDown(self):self.reader.stop();self.patch.stop();self.temp.cleanup()
    def run_flow(self):
        return c.capture_and_restore(r,b,self.pg,Path('/synthetic/tools'),self.local_cat,self.local_rights,
                                     tunnel_factory=self.Tunnel,snapshot_factory=self.Snapshot)
    def setup_local(self):self.local_cat=self.cat;self.local_rights=self.rights
    def test_single_capture_restore_and_receipts_do_not_rewrite_original_hold(self):
        self.setup_local();(self.root/'RESULT.json').write_bytes(b'ORIGINAL HOLD')
        result=self.run_flow();self.assertEqual((self.root/'RESULT.json').read_bytes(),b'ORIGINAL HOLD')
        self.assertEqual(self.calls.count('tunnel'),1);self.assertEqual(self.calls.count('dump'),1)
        self.assertLess(self.calls.index('rollback'),self.calls.index('finish'))
        self.assertTrue(result['snapshot_rollback_acknowledged']);self.assertEqual(result['snapshot']['fingerprints'],result['restored_fingerprints'])
        self.pg.restore_copies.assert_called_once();self.assertTrue((self.root/'restored-catalog.jsonl').exists())
    def test_capture_deadline_prevents_local_import_even_after_rollback(self):
        self.setup_local()
        with patch.object(c.time,'monotonic',side_effect=(1,302)):
            with self.assertRaisesRegex(c.Denied,'CAPTURE_DEADLINE'):self.run_flow()
        self.pg.restore_copies.assert_not_called()
    def test_unknown_tunnel_close_prevents_import_after_known_rollback(self):
        self.setup_local()
        def unknown(s):raise c.Denied('E1_TUNNEL_CLOSE_UNCONFIRMED')
        self.Tunnel.finish=unknown
        with self.assertRaisesRegex(c.Denied,'CLOSE_UNCONFIRMED'):self.run_flow()
        self.pg.restore_copies.assert_not_called();self.assertEqual(self.calls.count('rollback'),1)
        self.assertEqual(self.calls.count('abort'),1)
    def test_root_admission_rechecks_bound_db_results_and_rejects_forged_success(self):
        self.setup_local();result=self.run_flow()
        scope={'original_sha256':{'files.json':'1'*64}}
        c.begin(r,'2'*64,'3'*64,scope)
        result.update(schema='TU1NZ_E1_DB_RESULT_V1',status=c.PASS,cleanup=[],scope_sha256='2'*64,review_sha256='3'*64,
            original_hold_sha256=c.OLD_RESULT,original_remote_closed_ACK_received=False,original_remote_cleanup_observed=False,
            host_mutations=False,production_restore=False,private_restore_cleanup={'own_cluster_removed':True,'own_socket_removed':True})
        (self.root/'DB_COMPLETION_RESULT.json').write_bytes(c.canonical(result));(self.root/'DB_COMPLETION_RESULT.json').chmod(0o600)
        c.checked_db_receipt(scope,'2'*64,'3'*64,r)
        for key,value in (('status','HOLD'),('snapshot_rollback_acknowledged',False),('cleanup',['UNCLEAR']),
                          ('original_remote_closed_ACK_received',True),('capture_seconds',300),('restore_seconds',300),
                          ('original_hold_sha256','0'*64)):
            changed={**result,key:value};(self.root/'DB_COMPLETION_RESULT.json').write_bytes(c.canonical(changed))
            with self.subTest(key=key),self.assertRaises(c.Denied):c.checked_db_receipt(scope,'2'*64,'3'*64,r)
        (self.root/'DB_COMPLETION_RESULT.json').write_bytes(c.canonical(result));(self.root/'s7.dump').write_bytes(b'PGDMPCORRUPT')
        with self.assertRaisesRegex(c.Denied,'ARCHIVE_READBACK'):c.checked_db_receipt(scope,'2'*64,'3'*64,r)
    def test_unknown_owner_metadata_retained_before_denial_no_data_dump_or_restore(self):
        self.setup_local();changed=copy.deepcopy(self.rows);changed[0]['owner']='UNKNOWN'
        self.cat=fixtures.CatalogBoundary().raw(changed)
        with self.assertRaisesRegex(r.Denied,'OWNER_UNKNOWN'):self.run_flow()
        self.assertEqual((self.root/'source-catalog.jsonl').read_bytes(),self.cat)
        self.assertNotIn('dump',self.calls);self.assertNotIn('fingerprint',self.calls);self.pg.restore_copies.assert_not_called()
        self.assertEqual(self.calls.count('rollback'),1);self.assertEqual(self.calls.count('abort'),1)
    def test_unknown_rights_denies_before_dump(self):
        self.setup_local();self.rights=self.rights.replace(b'false',b'true')
        with self.assertRaisesRegex(r.Denied,'RIGHTS_DIFFER'):self.run_flow()
        self.assertTrue((self.root/'source-rights.jsonl').exists());self.assertNotIn('dump',self.calls)
    def test_partial_or_executable_dump_never_imported(self):
        self.setup_local();self.render=b'COPY public.commercial_s7_waitlist (id) FROM stdin;\nPARTIAL'
        with self.assertRaises(r.Denied):self.run_flow()
        self.pg.restore_copies.assert_not_called();self.assertEqual(self.calls.count('tunnel'),1)
    def test_unknown_rollback_ack_prevents_restore_and_still_tears_down_tunnel(self):
        self.setup_local()
        def lost(s):self.calls.append('rollback');raise r.Denied('SNAPSHOT_CLOSE_UNCONFIRMED')
        self.Snapshot.close=lost
        with self.assertRaisesRegex(r.Denied,'CLOSE_UNCONFIRMED'):self.run_flow()
        self.pg.restore_copies.assert_not_called();self.assertEqual(self.calls.count('rollback'),1);self.assertEqual(self.calls.count('abort'),1)
    def test_channel_lost_before_dump_cleans_snapshot_and_denies(self):
        self.setup_local()
        def lost(s):raise c.Denied('E1_CHANNEL_LOST_OR_DEADLINE')
        self.Tunnel.live=lost
        with self.assertRaisesRegex(c.Denied,'CHANNEL_LOST'):self.run_flow()
        self.assertNotIn('dump',self.calls);self.assertEqual(self.calls.count('rollback'),1);self.assertEqual(self.calls.count('abort'),1)
    def test_new_source_fingerprint_cannot_be_called_same_snapshot(self):
        self.setup_local();original=self.Snapshot.read;count=0
        def changed(s,kind,*a):
            nonlocal count
            raw=original(s,kind,*a)
            if kind=='fingerprint':
                count+=1
                if count>2:return b'DIFFERENT\n'
            return raw
        self.Snapshot.read=changed
        with self.assertRaisesRegex(c.Denied,'SNAPSHOT_DRIFT'):self.run_flow()
        self.pg.restore_copies.assert_not_called()


@unittest.skipUnless(os.geteuid()==0,'actual root output custody verified by Linux native job')
class RootOutput(unittest.TestCase):
    def test_root_receipt_is_private_user_owned_create_only(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(e,'OUTPUT',Path(temp).resolve()):
            fd=os.open(e.OUTPUT,os.O_RDONLY|os.O_DIRECTORY)
            try:
                e.write_receipt(fd,'FILE_RESTORE_RESULT.json',b'{"synthetic":true}')
                s=(e.OUTPUT/'FILE_RESTORE_RESULT.json').stat()
                self.assertEqual((s.st_uid,s.st_gid,s.st_mode&0o777),(501,20,0o600))
                with self.assertRaises(FileExistsError):e.write_receipt(fd,'FILE_RESTORE_RESULT.json',b'change')
                with self.assertRaises(e.Denied):e.write_receipt(fd,'RESULT.json',b'change')
            finally:os.close(fd)


if __name__=='__main__':unittest.main()
