"""Local no-Host entry/custody regressions; no native timing claim."""
import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
from contextlib import ExitStack
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as c
io=c.io

class EntryTests(unittest.TestCase):
    def test_rev4_dispatcher_does_not_dispatch_legacy_or_generate_a_second_entry(self):
        raw=Path(io.__file__).read_bytes()
        program=c.maintenance_bootstrap(raw)
        self.assertIn('dispatch_maintenance(s,p,w)',program)
        self.assertNotIn('.session(s,p,w)',program)
        compile(program,'<no-execution>','exec')
        self.assertIn('.session(s,p,w)',c.bootstrap(raw))

    def test_clock_starts_at_entry_even_if_validation_consumes_time(self):
        started=time.monotonic()-17
        transport=c.MaintenanceTransport(reserve_milliseconds=12000,started=started)
        self.assertEqual(transport.deadline,started+600)
        self.assertEqual(transport.work_deadline,started+588)
        self.assertLess(transport.remaining(),572)
        self.assertEqual(transport.close(),[])
        for value in (True,float('nan'),float('inf'),time.monotonic()+100):
            with self.subTest(value=value),self.assertRaises(io.Hold):
                c.MaintenanceTransport(reserve_milliseconds=12000,started=value)

    def test_packaging_is_canonical_bounded_and_pure(self):
        raws=[io.canonical({'field':n}) for n in range(4)]
        with patch.object(c.os,'open') as opening,patch.object(c.subprocess,'Popen') as spawning:
            packet=c.maintenance_package({}, {}, raws[0],raws[1],b'PLAN',raws[2],{'review':raws[3]},'a'*64)
        opening.assert_not_called();spawning.assert_not_called()
        self.assertEqual(packet['route'],'original');self.assertEqual(packet['remaining_milliseconds'],600000)
        self.assertNotIn('recovery',packet)
        for index in (0,1,2):
            changed=list(raws);changed[index]+=b'\n'
            with self.subTest(index=index),self.assertRaises(io.Hold):
                c.maintenance_package({}, {}, changed[0],changed[1],b'PLAN',changed[2],{},'a'*64)
        with self.assertRaises(io.Hold):c.maintenance_package({}, {},raws[0],raws[1],b'PLAN',raws[2],
            {'review':b'x'*io.MAX_FRAME},'a'*64)

    def invoke_inert(self, *, client_fault=False, recovery_fault=False):
        events=[]; host_error='PUBLIC_BOOTSTRAP_SYNTHETIC_HOST_FIRST'
        result={'type':'final','status':'HOLD','primary':host_error,'abort':[],
                'cleanup':['PUBLIC_BOOTSTRAP_SYNTHETIC_HOST_CLOSE']}
        packet={'route':'original','binding':'a'*64,'hashes':{},'baseline':{'boot_id':'synthetic',
                'http':{'u1':[],'u2':[],'u3':[],'lighting':{'location':'host'}}}}
        r=SimpleNamespace(UNITS=('u1','u2','u3'),CUSTODY_PARENT=Path('/INERT-NOT-OPENED'),TX='public-rights-20261014-1')
        source=SimpleNamespace(load=lambda name:r if name=='r3' else SimpleNamespace(validate=Mock()))
        class Transport:
            def __init__(self,**kw):
                self.started=kw['started'];self.deadline=self.started+600;self.work_deadline=self.deadline-10
                self.child=SimpleNamespace(returncode=0)
            def connect(self,*a,**kw):events.append('connect');return SimpleNamespace(deadline=self.work_deadline),packet
            def close(self):events.append('transport_close');return []
            def remaining(self,**kw):return 10
        class Client:
            def __init__(self,*a,**kw):self.binding=self.last='a'*64;self.sequence=2;self.fd='INERT'
            def admission_current(self):events.append('admission')
            def initialize(self):events.append('entry')
            def serve(self):events.append('serve');return result
            def check(self):
                if client_fault:raise io.Hold('PUBLIC_OPERATOR_SYNTHETIC_LATER_CLIENT')
            def close(self):events.append('client_close')
        with ExitStack() as stack:
            stack.enter_context(patch.object(io,'maintenance_packet_binding',return_value={
                'documents':{'native_timing':{'transport_cleanup_reserve_milliseconds':10000}}}))
            stack.enter_context(patch.object(c,'MaintenanceTransport',Transport))
            stack.enter_context(patch.object(c,'MaintenanceClient',Client))
            stack.enter_context(patch.object(c.RecoveryCustody,'directory_identity',return_value='INERT'))
            stack.enter_context(patch.object(c,'maintenance_closed_chain',return_value={'tail':'b'*64,'count':2}))
            saved=stack.enter_context(patch.object(c,'maintenance_cleanup_receipt',return_value='c'*64))
            if recovery_fault:stack.enter_context(patch.object(c,'RecoveryCustody',side_effect=io.Hold('PUBLIC_OPERATOR_RECOVERY_SPENT')))
            value=c.execute_maintenance(packet,source,password=b'SYNTHETIC_NOT_A_PASSWORD',runtime_payload=b'',recover_once=recovery_fault)
        return value,events,saved

    def test_host_primary_survives_later_client_error_and_cleanup_remains_separate(self):
        for fail in (False,True):
            with self.subTest(client_fault=fail):
                result,events,saved=self.invoke_inert(client_fault=fail)
                self.assertEqual(result['status'],'HOLD');self.assertEqual(result['primary'],'PUBLIC_BOOTSTRAP_SYNTHETIC_HOST_FIRST')
                self.assertEqual(result['host_cleanup'],['PUBLIC_BOOTSTRAP_SYNTHETIC_HOST_CLOSE'])
                self.assertEqual(result['client_primary'], 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_SYNTHETIC_LATER_CLIENT' if fail else None)
                self.assertLess(events.index('entry'),events.index('connect'))
                self.assertLess(events.index('client_close'),events.index('transport_close'))
                receipt=saved.call_args.args[2];self.assertFalse(receipt['completion_claimed'])
                self.assertEqual(receipt['primary'],result['host_primary'])

    def test_spent_recovery_is_denied_before_any_transport(self):
        result,events,saved=self.invoke_inert(recovery_fault=True)
        self.assertEqual(result['status'],'HOLD');self.assertNotIn('connect',events)
        self.assertIn('RECOVERY_SPENT',result['client_primary']);saved.assert_not_called()

    def fixture(self, *, success=False):
        tmp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);root.chmod(0o700)
        binding='a'*64
        value={'status':'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED' if success else 'HOLD',
            'primary':None if success else 'PUBLIC_BOOTSTRAP_SYNTHETIC_INTERRUPTION',
            'abort':[],'cleanup':[],'owner_completion_sha256':'b'*64 if success else None,
            'original_status':'THIS_RUN','original_evidence':None,'client_cleanup_still_required':True,'r2_dispatch':False}
        row={'binding':binding,'previous':binding,'sequence':1,'kind':'operator_cleanup','value':value}
        final={'type':'final',**value,'source_fault':None,'slot_consumed':False}
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            io.exclusive(fd,'001-operator_cleanup.json',io.canonical(row))
            io.exclusive(fd,'final.json',io.canonical(final));identity=c.RecoveryCustody.directory_identity(fd)
        finally:os.close(fd)
        receipt={'type':'client-cleanup','schema':'TU1NZ_REV4_CLIENT_CLEANUP_V1','route':'original',
            'original_binding':binding,'execution_binding':binding,'status':'CLEANUP_OBSERVED_PENDING_READBACK' if success else 'HOLD',
            'completion_claimed':False,'original_status':'THIS_RUN',
            'host_final_sha256':io.sha(io.canonical(final)),'tail_sha256':io.sha(io.canonical(row)),
            'sequence':1,'primary':value['primary'],'abort':[],'host_cleanup':[],'client_primary':None,'cleanup':[],'ssh_exit':0,'operational_handles_closed':True,
            'remote_ACK_reconstructed':False}
        return root,binding,final,receipt,identity

    def test_success_requires_independent_closed_chain_and_exclusive_result_readback(self):
        root,binding,final,receipt,identity=self.fixture(success=True)
        proof=c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)
        self.assertEqual(proof['tail'],receipt['tail_sha256'])
        digest=c.maintenance_cleanup_receipt(root,identity,receipt,deadline=time.monotonic()+10)
        self.assertEqual(digest,io.sha(io.private_read(root/'client-cleanup.json')))
        again=c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)
        self.assertEqual(again['count'],1)
        with self.assertRaises(FileExistsError):c.maintenance_cleanup_receipt(root,identity,receipt,deadline=time.monotonic()+10)

    def test_mismatching_final_tail_status_or_missing_cleanup_never_becomes_success(self):
        root,binding,final,receipt,identity=self.fixture(success=True)
        with self.assertRaises(io.Hold):c.maintenance_closed_chain(root,binding,{**final,'cleanup':['unexpected']},deadline=time.monotonic()+10)
        (root/'001-operator_cleanup.json').unlink()
        with self.assertRaises(io.Hold):c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)

    def test_failed_receipt_preserves_unknown_ack_and_does_not_reset_original(self):
        root,binding,final,receipt,identity=self.fixture()
        originals={p.name:p.read_bytes() for p in root.iterdir()}
        c.maintenance_cleanup_receipt(root,identity,receipt,deadline=time.monotonic()+10)
        proof=c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)
        self.assertEqual(proof['supplements']['client-cleanup.json']['record']['status'],'HOLD')
        self.assertTrue(all((root/n).read_bytes()==raw for n,raw in originals.items()))
        for key,value in (('tail_sha256','c'*64),('sequence',2),('host_final_sha256',None),('execution_binding','d'*64)):
            changed={**receipt,key:value}
            with self.subTest(key=key),self.assertRaises(io.Hold):
                io.validate_cleanup_tail({'client-cleanup.json':{'record':changed},'final.json':
                    {'sha256':receipt['host_final_sha256']}},binding,receipt['tail_sha256'],1)

    def test_expiry_after_write_preserves_pending_evidence_never_complete(self):
        root,binding,final,receipt,identity=self.fixture(success=True)
        now=time.monotonic()
        with patch.object(c.time,'monotonic',side_effect=[now,now+11]),self.assertRaises(io.Hold):
            c.maintenance_cleanup_receipt(root,identity,receipt,deadline=now+10)
        saved=io.parse(io.private_read(root/'client-cleanup.json'))
        self.assertEqual(saved['status'],'CLEANUP_OBSERVED_PENDING_READBACK')
        self.assertIs(saved['completion_claimed'],False)

    def test_cleanup_deadline_or_unknown_child_cannot_grant_success(self):
        root,binding,final,receipt,identity=self.fixture(success=True)
        with self.assertRaises(io.Hold):c.maintenance_cleanup_receipt(root,identity,receipt,deadline=time.monotonic()-1)
        self.assertFalse((root/'client-cleanup.json').exists())
        for key,value in (('ssh_exit',None),('operational_handles_closed',False),('host_final_sha256',None),
                          ('primary','PUBLIC_BOOTSTRAP_SYNTHETIC_FAILURE'),('cleanup',['PUBLIC_BOOTSTRAP_SYNTHETIC_CLOSE'])):
            with self.subTest(key=key),self.assertRaises(io.Hold):io.client_cleanup_record({**receipt,key:value})

if __name__=='__main__':unittest.main()
