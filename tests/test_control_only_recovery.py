"""Portable object/slot tests plus isolated native real-transition scenarios."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_control_recovery_contract as c
import tu1nz_control_recovery_authority as a


def capsule_bytes():
    blob=b'synthetic\n';bid=c.oid('blob',blob)
    tree=b'100644 tracked.txt\0'+bytes.fromhex(bid);tid=c.oid('tree',tree)
    commit=b'tree '+tid.encode()+b'\nauthor Synthetic <s@example.invalid> 1 +0000\ncommitter Synthetic <s@example.invalid> 1 +0000\n\nSynthetic\n'
    cid=c.oid('commit',commit)
    target={'repository':c.TARGET['repository'],'commit':cid,'tree':tid}
    values={o:{'kind':k,'data':base64.b64encode(raw).decode()} for o,k,raw in
            ((cid,'commit',commit),(tid,'tree',tree),(bid,'blob',blob))}
    return c.canonical({'schema':c.SCHEMA+'_CAPSULE','target':target,'objects':values}),target


class Portable(unittest.TestCase):
    def test_open_host_gates_never_spend_or_launch(self):
        with tempfile.TemporaryDirectory() as name:
            root,mirror=Path(name)/'a',Path(name)/'b';root.mkdir(mode=0o700);mirror.mkdir(mode=0o700)
            with self.assertRaises(c.RecoveryError):
                a.transport_once(lambda:self.fail('launch before host acceptance'),b'{}',root/'missing-key',
                    root,mirror,release={'packet_sha256':c.digest(b'{}'),'host_gates':'UNKNOWN'})
            self.assertEqual(list(root.iterdir()),[]);self.assertEqual(list(mirror.iterdir()),[])

    def test_remote_argv_is_exact_return_only_and_rejects_injection(self):
        from tu1nz_control_recovery_entry import remote_argv
        argv=remote_argv('a'*64)
        self.assertEqual(argv[-2],'chatops@100.121.130.51')
        self.assertIn('/usr/bin/timeout',argv[-1]);self.assertIn('40s',argv[-1])
        self.assertNotIn('systemctl',argv[-1]);self.assertNotIn('restart',argv[-1])
        with self.assertRaises(c.RecoveryError):remote_argv('a'*63+';')

    def test_target_ancestry_is_authenticated_not_a_shallow_claim(self):
        raw,target=capsule_bytes();value=json.loads(raw)
        parent=target['commit'];data=base64.b64decode(value['objects'][parent]['data'])
        new=data.replace(b'author ',b'parent '+parent.encode()+b'\nauthor ',1)
        child=c.oid('commit',new);value['objects'][child]={'kind':'commit','data':base64.b64encode(new).decode()}
        target={**target,'commit':child};value['target']=target
        capsule=c.Capsule(c.canonical(value),target)
        self.assertIn(parent,capsule.history_done)
        self.assertEqual(capsule.release_files()['.git/HEAD'][0],b'ref: refs/heads/main\n')
        self.assertNotIn('.git/shallow',capsule.release_files())
        del value['objects'][parent]
        with self.assertRaises(c.RecoveryError):c.Capsule(c.canonical(value),target)
    def test_frozen_entry_bootstrap_uses_no_host_imports_and_rejects_packet_drift(self):
        from tu1nz_control_recovery_entry import BOOTSTRAP,MODULES,PUBLIC_SHA
        self.assertEqual(len(set(MODULES)),7)
        self.assertEqual(c.digest((Path(__file__).resolve().parents[1]/'config/control-only-recovery/authority-ed25519.pub').read_bytes()),PUBLIC_SHA)
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',BOOTSTRAP,'0'*64],
                              input=b'{}\n',capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')
    def test_complete_tree_and_generated_index_independent_object_hashes(self):
        raw,target=capsule_bytes();cap=c.Capsule(raw,target)
        self.assertEqual(cap.files['tracked.txt']['bytes'],b'synthetic\n')
        self.assertEqual(c.index_entries(c.index_bytes(cap.files))['tracked.txt']['oid'],cap.files['tracked.txt']['oid'])

    def test_corrupt_object_missing_object_wrong_tree_and_extra_object_deny(self):
        raw,target=capsule_bytes()
        for defect in ('corrupt','missing','tree','extra'):
            value=json.loads(raw)
            blob=next(k for k,v in value['objects'].items() if v['kind']=='blob')
            if defect=='corrupt':value['objects'][blob]['data']=base64.b64encode(b'changed').decode()
            elif defect=='missing':del value['objects'][blob]
            elif defect=='tree':value['target']['tree']='f'*40
            else:
                data=b'extra';value['objects'][c.oid('blob',data)]={'kind':'blob','data':base64.b64encode(data).decode()}
            with self.subTest(defect=defect),self.assertRaises(c.RecoveryError):c.Capsule(c.canonical(value),target)

    def test_index_checksum_truncation_and_unmerged_are_not_accepted(self):
        raw,target=capsule_bytes();cap=c.Capsule(raw,target);index=c.index_bytes(cap.files)
        for bad in (b'',index[:-1],index[:20]+b'bad'+index[23:]):
            with self.assertRaises(c.RecoveryError):c.index_entries(bad)
        damaged=bytearray(index[:-20]);damaged[72:74]=(0x1000|len('tracked.txt')).to_bytes(2,'big')
        import hashlib
        with self.assertRaises(c.RecoveryError):c.index_entries(bytes(damaged)+hashlib.sha1(damaged).digest())

    def test_unsafe_tree_names_and_submodules_deny(self):
        for name in ('../x','.git','x/y','/x'):
            raw=b'100644 '+name.encode()+b'\0'+bytes.fromhex('a'*40)
            with self.assertRaises(c.RecoveryError):c.tree_entries(raw)
        with self.assertRaises(c.RecoveryError):c.tree_entries(b'160000 submodule\0'+bytes.fromhex('a'*40))

    def test_single_dispatch_exception_and_lost_reply_never_retry(self):
        with tempfile.TemporaryDirectory() as name:
            root,mirror=Path(name)/'a',Path(name)/'b';root.mkdir(mode=0o700);mirror.mkdir(mode=0o700)
            calls=[]
            def dispatch(_):calls.append(1);raise RuntimeError('synthetic lost reply')
            with self.assertRaises(RuntimeError):a.supervise_single_dispatch(dispatch,root,mirror,release={})
            with self.assertRaises(c.RecoveryError):a.supervise_single_dispatch(dispatch,root,mirror,release={})
            self.assertEqual(calls,[1])

    def test_partial_or_mismatched_client_marker_is_not_repaired(self):
        with tempfile.TemporaryDirectory() as name:
            root,mirror=Path(name)/'a',Path(name)/'b';root.mkdir(mode=0o700);mirror.mkdir(mode=0o700)
            marker=root/(c.SLOT+'.attempt.json');marker.write_bytes(b'partial')
            with self.assertRaises(c.RecoveryError):a.spend_before_dispatch(root,mirror,release={})
            self.assertEqual(marker.read_bytes(),b'partial')
            self.assertFalse((mirror/marker.name).exists())


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and os.environ.get('container')=='docker'
                     and os.environ.get('TU1NZ_CONTROL_NATIVE_ROOT'),'isolated native ext4 only')
class Native(unittest.TestCase):
    def run_case(self,name):
        base=Path(os.environ['TU1NZ_CONTROL_NATIVE_ROOT'])/('case-'+name)
        result=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).with_name('control_recovery_scenarios.py')),
            '--case',name,'--base',str(base)],capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
        value=json.loads(result.stdout);self.assertTrue(value['passed'])


for case in ('entry','success','large-stock','hardlinks','acl','lost-confirmation','capless-sealed','capless-metadata','ancestor-replay',
             'revoke','revoke-failure','late-completion-failure','missing-completion','completion-drift',
             'competing-anchor','multiple-errors','application-change','interrupt-COMPLETION_WRITTEN',
             'source-origin','missing-worktree','bad-index',
             'missing-head-subtree','corrupt-head-subtree',
             'writer','namespace-source','extra-output','corrupt-backup','marker-change','metadata-aba',
             'existing-anchor','wrong-target','wrong-signature','interrupt-CLAIM_DURABLE',
             'interrupt-BACKUP_READBACK','interrupt-RESTORE_TESTED','interrupt-RELEASE_SEALED',
             'interrupt-RECEIPT_WRITTEN'):
    setattr(Native,'test_'+case.replace('-','_'),lambda self,name=case:self.run_case(name))


if __name__=='__main__':unittest.main()
