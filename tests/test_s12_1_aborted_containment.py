"""R15 source-only: real Linux mixed metadata, no runtime/provider calls."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s12_1_r12_metadata_contract import fixture


class ProvenanceTests(unittest.TestCase):
    def test_primary_abort_cleanup_and_logging_are_independent(self):
        events=[]; cleaned=[]
        def persist(path,payload):
            events.append(json.loads(payload));raise OSError('secret must not be printed')
        with mock.patch.object(r,'_write_private_backup_blob',side_effect=persist):
            errors=r._MetadataErrors('TEST')
            primary=r.S12ControlError('PRIMARY_RED');abort=r.S12ControlError('ABORT_RED')
            errors.record('primary',primary);errors.record('abort',abort)
            def bad():
                cleaned.append('bad');raise OSError(5,'private detail')
            errors.cleanup([('first',bad),('last',lambda:cleaned.append('last'))])
        self.assertEqual(cleaned,['bad','last'])
        self.assertEqual([e['event']['channel'] for e in events],['primary','abort','cleanup'])
        self.assertEqual([e['channel'] for e in primary.metadata_errors],
                         ['primary','logging','abort','logging','cleanup','logging'])
        self.assertNotIn('private detail',json.dumps(primary.metadata_errors))

    def test_all_cleanup_runs_even_if_first_raises_without_primary(self):
        called=[]
        with mock.patch.object(r,'_write_private_backup_blob'):
            errors=r._MetadataErrors('TEST')
            def fail():raise r.S12ControlError('CLEANUP_RED')
            with self.assertRaisesRegex(r.S12ControlError,'CLEANUP_RED') as caught:
                errors.cleanup([('first',fail),('second',lambda:called.append(True))])
        self.assertEqual(called,[True])
        self.assertEqual(caught.exception.metadata_errors[0]['channel'],'cleanup')

    def test_containment_cannot_grant_recovery_or_reconciliation(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(r,'STATE_ROOT',Path(name)):
            (Path(name)/'repository-barrier.r15-containment.json').write_bytes(b'partial claim')
            for operation in (r._recover_locked,r._deploy_locked):
                with self.assertRaisesRegex(r.S12ControlError,'NO_RUNTIME_AUTHORITY'):operation()
            with self.assertRaisesRegex(r.S12ControlError,'NO_RUNTIME_AUTHORITY'):
                r.followup(Path('never-read'),'unused')


@contextmanager
def aborted_fixture(full=False):
    with fixture(mixed_254=full) as f:
        persist=r._atomic_barrier_json
        index=235 if full else 2
        fired=False
        def abort_at_intent(path,payload):
            nonlocal fired
            persist(path,payload)
            if path.name=='repository-barrier.r12-bindings.json' and payload.get('phase')=='PREPARED':
                b=payload['bindings'][index]
                if b['intent']==len(b['states'])-1 and not fired:
                    fired=True;raise r.S12ControlError('SYNTHETIC_PRIMARY_AT_PENDING_CHMOD')
        with mock.patch.object(r,'_atomic_barrier_json',side_effect=abort_at_intent):
            with unittest.TestCase().assertRaisesRegex(r.S12ControlError,'SYNTHETIC_PRIMARY'):
                r.reconcile_metadata(f['contract'])
        assert fired
        ledger=f['state']/'repository-barrier.r12-bindings.json'
        receipt=f['state']/'repository-barrier.r12-abort.json'
        f['aborted_bytes']=ledger.read_bytes();f['receipt_bytes']=receipt.read_bytes()
        with mock.patch.object(r,'ABORTED_BINDINGS_SHA256',hashlib.sha256(f['aborted_bytes']).hexdigest()),\
             mock.patch.object(r,'ABORTED_RECEIPT_SHA256',hashlib.sha256(f['receipt_bytes']).hexdigest()):
            yield f


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'native Linux root and unchanged kernel guards required')
class NativeTests(unittest.TestCase):
    def preserved(self,f):
        self.assertEqual((f['state']/'repository-barrier.r12-bindings.json').read_bytes(),f['aborted_bytes'])
        self.assertEqual((f['state']/'repository-barrier.r12-abort.json').read_bytes(),f['receipt_bytes'])
        self.assertEqual(json.loads(r.BARRIER_MARKER.read_bytes()),f['original'])
        for root in (f['app'],f['control']):
            self.assertEqual(stat.S_IMODE((root/'.git').stat().st_mode),0)
        self.assertFalse((f['state']/(r.FOLLOWUP_SLOT+'.consumed.json')).exists())

    def assert_contained(self,f):
        old=json.loads(f['aborted_bytes'])
        for b in old['bindings']:
            p=Path(b['path']);fd=r._r12_open(p)
            try:
                e=next(e for e in f['entries'] if p==Path(json.loads(f['contract'].read_bytes())['roots'][e['repository']])/e['path'])
                actual=r._r12_snapshot(p,fd,e['content_sha256'])
            finally:os.close(fd)
            self.assertEqual(actual,{k:v for k,v in b['states'][-1].items() if k!='operation'})
            self.assertEqual(actual['metadata']['uid'],0)
            self.assertFalse(int(actual['metadata']['mode'],8)&0o222)

    def test_real_254_mixed_state_contained_without_replaying_pending_noop(self):
        with aborted_fixture(full=True) as f:
            ledger=json.loads(f['aborted_bytes']);pending=[b for b in ledger['bindings'] if b['intent'] is not None]
            self.assertEqual(len(ledger['bindings']),254)
            self.assertEqual(sum(b['step']==len(b['states'])-1 for b in ledger['bindings']),235)
            self.assertEqual(sum(b['step']==0 for b in ledger['bindings']),18)
            self.assertEqual(len(pending),1)
            p=Path(pending[0]['path']);before=p.stat().st_ctime_ns
            result=r.contain_aborted_metadata(f['contract'])
            self.assertEqual(result['phase'],'CLOSED_CONTAINED')
            self.assertEqual(p.stat().st_ctime_ns,before)
            self.assertFalse(result['metadata_rolled_back']);self.assertFalse(result['deployment_allowed'])
            self.assert_contained(f);self.preserved(f)
            stable={Path(b['path']):Path(b['path']).stat().st_ctime_ns for b in ledger['bindings']}
            self.assertEqual(r.contain_aborted_metadata(f['contract'])['target_mutations'],0)
            self.assertEqual(stable,{p:p.stat().st_ctime_ns for p in stable})
            self.preserved(f)

    def test_original_or_current_drift_never_adopted(self):
        for kind in ('content','mode','owner','replace','hardlink','ledger','receipt'):
            with self.subTest(kind=kind),aborted_fixture() as f:
                p=f['app']/'kept'
                if kind=='content':p.write_bytes(b'foreign')
                elif kind=='mode':p.chmod(0o644)
                elif kind=='owner':os.chown(p,1002,1001)
                elif kind=='replace':p.rename(f['base']/'old');p.write_bytes(b'target\n')
                elif kind=='hardlink':os.link(p,f['base']/'alias')
                else:
                    p=f['state']/('repository-barrier.r12-bindings.json' if kind=='ledger' else 'repository-barrier.r12-abort.json')
                    p.write_bytes(p.read_bytes()+b' ')
                with self.assertRaises(r.S12ControlError):r.contain_aborted_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r15-containment.json').exists())

    def test_interruption_claim_intent_syscall_and_closing_never_replays(self):
        class Interrupted(BaseException):pass
        for seam in ('claim','intent','syscall','closed'):
            with self.subTest(seam=seam),aborted_fixture() as f:
                save=r._write_private_backup_blob;atomic=r._atomic_barrier_json;setacl=os.setxattr
                fired=False
                def blob(path,payload):
                    nonlocal fired
                    if seam=='closed' and path.name=='repository-barrier.r15-contained.json':
                        fired=True;raise Interrupted()
                    value=save(path,payload)
                    if seam=='claim' and path.name=='repository-barrier.r15-containment.json':
                        fired=True;raise Interrupted()
                    return value
                def progress(path,payload):
                    nonlocal fired
                    atomic(path,payload)
                    if seam=='intent' and path.name=='repository-barrier.r15-containment-progress.json' and payload['intent'] is not None:
                        fired=True;raise Interrupted()
                def syscall(fd,*args):
                    nonlocal fired
                    result=setacl(fd,*args)
                    if seam=='syscall' and isinstance(fd,int) and not fired:
                        fired=True;raise Interrupted()
                    return result
                with mock.patch.object(r,'_write_private_backup_blob',side_effect=blob),\
                     mock.patch.object(r,'_atomic_barrier_json',side_effect=progress),\
                     mock.patch.object(os,'setxattr',side_effect=syscall):
                    with self.assertRaises(Interrupted):r.contain_aborted_metadata(f['contract'])
                self.assertTrue(fired)
                before={b['path']:Path(b['path']).stat().st_ctime_ns for b in json.loads(f['aborted_bytes'])['bindings']}
                with self.assertRaisesRegex(r.S12ControlError,'INCOMPLETE_NO_RETRY'):r.contain_aborted_metadata(f['contract'])
                self.assertEqual(before,{p:Path(p).stat().st_ctime_ns for p in before})
                self.preserved(f)

    def test_retained_writer_and_late_reverted_attribute_conflict(self):
        for kind in ('retained','late'):
            with self.subTest(kind=kind),aborted_fixture() as f:
                child=None;atomic=r._atomic_barrier_json;fired=False
                def progress(path,payload):
                    nonlocal fired
                    atomic(path,payload)
                    if kind=='late' and path.name=='repository-barrier.r15-containment-progress.json' and not fired:
                        fired=True
                        subprocess.run([sys.executable,'-c','import os,sys;p=sys.argv[1];m=os.stat(p).st_mode&4095;os.chmod(p,384);os.chmod(p,m)',str(f['app']/'kept')],check=True)
                try:
                    if kind=='retained':
                        child=subprocess.Popen([sys.executable,'-c','import sys;f=open(sys.argv[1],"r+b");print("ready",flush=True);sys.stdin.read()',str(f['app']/'kept')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
                        self.assertEqual(child.stdout.readline().strip(),'ready')
                    with mock.patch.object(r,'_atomic_barrier_json',side_effect=progress):
                        with self.assertRaises(r.S12ControlError):r.contain_aborted_metadata(f['contract'])
                finally:
                    if child:child.communicate('',timeout=5)
                self.assertFalse((f['state']/'repository-barrier.r15-contained.json').exists())
                self.preserved(f)

    def test_failed_cleanup_cannot_publish_closed_or_skip_other_cleanup(self):
        with aborted_fixture() as f:
            close=r._GuardedHandleQuiescence.close
            def failed_close(self):close(self);raise r.S12ControlError('SYNTHETIC_CLEANUP_RED')
            with mock.patch.object(r._GuardedHandleQuiescence,'close',failed_close):
                with self.assertRaisesRegex(r.S12ControlError,'SYNTHETIC_CLEANUP_RED') as caught:
                    r.contain_aborted_metadata(f['contract'])
            self.assertEqual(caught.exception.metadata_errors[-1]['channel'],'cleanup')
            self.assertFalse((f['state']/'repository-barrier.r15-contained.json').exists())
            with self.assertRaisesRegex(r.S12ControlError,'INCOMPLETE_NO_RETRY'):r.contain_aborted_metadata(f['contract'])
            self.preserved(f)

    def test_terminal_repeat_rejects_drift_instead_of_returning_cached_green(self):
        with aborted_fixture() as f:
            r.contain_aborted_metadata(f['contract'])
            p=f['app']/'kept';p.chmod(0o640)
            with self.assertRaises(r.S12ControlError):r.contain_aborted_metadata(f['contract'])
            self.preserved(f)


if __name__=='__main__':unittest.main()
