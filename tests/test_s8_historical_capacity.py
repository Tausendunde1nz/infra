"""Derived budget/cleanup regressions; synthetic process resources only."""
import errno
import os
from pathlib import Path
import resource
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_historical_capacity as cap

ROOTS=(Path('/opt/tu1nz_repos/application'),Path('/opt/tu1nz_repos/control'))
HISTORY=Path('/etc/tu1nz/private/state')


class BudgetTests(unittest.TestCase):
    def plan(self,held=None,inventory=None):
        return cap.requirements(ROOTS,HISTORY,4,5,
            inventory or [dict(nodes=3500,pack_indexes=2),dict(nodes=3500,pack_indexes=3)],
            {0:(0,),1:(1,),2:(2,)} if held is None else held)

    def test_exact_parts_no_fixed_big_limit(self):
        p=self.plan()
        self.assertEqual(p['breakdown'],dict(git_inputs=7000,ancestry=76,evidence=4,
            evidence_lease_watches=4,git_lease_and_namespace_watches=4,
            pack_mapping_fds=6,transient_and_cleanup_reserve=8))
        self.assertEqual(p['required_soft'],7105)

    def test_sparse_occupied_fd_slots_not_only_count(self):
        p=self.plan({0:(0,),8000:(1,)})
        self.assertEqual(p['held_count'],2)
        self.assertEqual(p['required_soft'],8001+7102)

    def test_changed_inventory_increases_budget(self):
        a=self.plan()
        b=self.plan(inventory=[dict(nodes=3600,pack_indexes=64),dict(nodes=3600,pack_indexes=2)])
        self.assertEqual(b['required_soft']-a['required_soft'],322)

    def test_missing_count_pack_scope_and_boolean_rejected(self):
        for row in ({},dict(nodes=True,pack_indexes=0),dict(nodes=65537,pack_indexes=0),
                    dict(nodes=3,pack_indexes=65),dict(nodes=3,pack_indexes=-1)):
            with self.subTest(row=row),self.assertRaises(c.ContractError):
                self.plan(inventory=[row,dict(nodes=3,pack_indexes=0)])
        with self.assertRaises(c.ContractError):cap.requirements(ROOTS,HISTORY,3,5,[],{})

    def context(self,*,raise_error=None,restore_error=None,body_error=None,readback_bad=False,fd_changed=False):
        held={0:(0,)};old=(1024,10000);state=list(old);calls=[]
        value=dict(required_soft=7105,previous_soft=1024,unchanged_hard=10000,soft_change_required=True)
        gets=0
        def get(_):
            nonlocal gets
            gets+=1
            return (1024,10000) if readback_bad and gets==1 else tuple(state)
        def set_(_,pair):
            calls.append(pair)
            if len(calls)==1 and raise_error:raise raise_error
            if len(calls)==2 and restore_error:raise restore_error
            state[:]=pair
        result=None;entered=False;evidence={}
        with patch.object(cap,'probe',return_value=(value,held)), \
             patch.object(cap,'descriptors',return_value={} if fd_changed else held), \
             patch.object(cap.resource,'getrlimit',side_effect=get), \
             patch.object(cap.resource,'setrlimit',side_effect=set_):
            try:
                with cap.capture_capacity(ROOTS,HISTORY,evidence):
                    entered=True
                    if body_error:raise body_error
            except BaseException as error:result=error
        return result,calls,entered,evidence,state

    def test_raise_exact_requirement_restore_hard_unchanged(self):
        error,calls,entered,evidence,state=self.context()
        self.assertIsNone(error);self.assertTrue(entered)
        self.assertEqual(calls,[(7105,10000),(1024,10000)])
        self.assertEqual(state,[1024,10000])
        self.assertTrue(evidence['fd_baseline_restored']);self.assertTrue(evidence['limit_restored'])

    def test_set_failure_before_protection_still_restores(self):
        primary=PermissionError(errno.EPERM,'synthetic')
        error,calls,entered,_,state=self.context(raise_error=primary)
        self.assertIs(error,primary);self.assertFalse(entered)
        self.assertEqual(state,[1024,10000]);self.assertEqual(len(calls),2)

    def test_readback_failure_before_protection(self):
        error,_,entered,_,state=self.context(readback_bad=True)
        self.assertRegex(str(error),'FD_LIMIT_READBACK_RED');self.assertFalse(entered)
        self.assertEqual(state,[1024,10000])

    def test_interrupt_preserves_primary_and_restores(self):
        primary=KeyboardInterrupt()
        error,_,entered,_,state=self.context(body_error=primary)
        self.assertIs(error,primary);self.assertTrue(entered);self.assertEqual(state,[1024,10000])

    def test_body_error_and_restore_provenance_separate(self):
        primary=c.ContractError('S8_EXECUTION_SYNTHETIC_PRIMARY')
        error,_,_,_,_=self.context(body_error=primary,restore_error=OSError(errno.EPERM,'private'))
        self.assertIs(error,primary)
        self.assertTrue(error._s8_cleanup_errors)
        self.assertNotIn('private',repr(error._s8_cleanup_errors))

    def test_restore_error_alone_is_red(self):
        error,_,_,_,_=self.context(restore_error=OSError(errno.EPERM,'private'))
        self.assertRegex(str(error),'FD_CLEANUP_RED')

    def test_leak_does_not_skip_limit_restore(self):
        error,_,_,_,state=self.context(fd_changed=True)
        self.assertRegex(str(error),'FD_CLEANUP_RED');self.assertEqual(state,[1024,10000])
        self.assertIn('FD_CAPTURE_LEAK_OR_BASELINE_CHANGED',repr(error._s8_cleanup_errors))

    def test_bad_evidence_no_limit_change(self):
        with patch.object(cap,'Capacity') as value,self.assertRaises(c.ContractError):
            with cap.capture_capacity(ROOTS,HISTORY,[]):pass
        value.assert_not_called()

    def test_hard_deny_before_capacity_or_set(self):
        with patch.object(cap.os,'uname') as uname,patch.object(cap.os,'listdir',return_value=['one']), \
             patch.object(cap,'descriptors',return_value={0:(0,)}), \
             patch.object(cap,'census',return_value=[dict(nodes=700,pack_indexes=0)]*2), \
             patch.object(cap.resource,'getrlimit',return_value=(1024,1024)), \
             patch.object(cap.resource,'setrlimit') as setter:
            uname.return_value.sysname='Linux'
            with self.assertRaisesRegex(c.ContractError,'FD_HARD_CAPACITY_INSUFFICIENT'):
                cap.probe(ROOTS,HISTORY)
            setter.assert_not_called()

    def test_sufficient_soft_no_set_no_infinity_request(self):
        value=dict(required_soft=7000,previous_soft=10000,unchanged_hard=20000,soft_change_required=False)
        with patch.object(cap,'probe',return_value=(value,{})),patch.object(cap,'descriptors',return_value={}), \
             patch.object(cap.resource,'getrlimit',return_value=(10000,20000)), \
             patch.object(cap.resource,'setrlimit') as setter:
            with cap.capture_capacity(ROOTS,HISTORY):pass
            setter.assert_not_called()


@unittest.skipUnless(sys.platform=='linux','native Linux resource context')
class NativeCapacityTests(unittest.TestCase):
    def test_real_threaded_process_cannot_change_reader_limit(self):
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        ready, release = threading.Event(), threading.Event()
        def held_thread():
            ready.set()
            release.wait(10)
        thread = threading.Thread(target=held_thread)
        thread.start()
        try:
            self.assertTrue(ready.wait(5))
            with self.assertRaisesRegex(c.ContractError, 'FD_DEDICATED_PROCESS_REQUIRED'):
                cap.probe(ROOTS, HISTORY)
            self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE), before)
        finally:
            release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_real_many_held_fds_and_transient_budget_restore(self):
        before=resource.getrlimit(resource.RLIMIT_NOFILE)
        self.assertTrue(before[1]==resource.RLIM_INFINITY or before[1]>2200)
        with tempfile.TemporaryDirectory(prefix='s8-fd-native-') as directory:
            base=Path(directory);roots=(base/'a',base/'b')
            for root in roots:
                git=root/'.git.s12-1-recovery';git.mkdir(parents=True)
                for i in range(600):(git/str(i)).write_bytes(b'')
            held=[os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC) for _ in range(17)]
            resource.setrlimit(resource.RLIMIT_NOFILE,(256,before[1]))
            handles=[];evidence={}
            try:
                with cap.capture_capacity(roots,base/'history',evidence):
                    self.assertLess(evidence['required_soft'],2200)
                    self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE)[0],evidence['required_soft'])
                    for _ in range(1202):handles.append(os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC))
                    for fd in reversed(handles):os.close(fd)
                    handles.clear()
                self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),(256,before[1]))
                self.assertTrue(evidence['fd_baseline_restored'])
            finally:
                for fd in reversed(handles):os.close(fd)
                resource.setrlimit(resource.RLIMIT_NOFILE,before)
                for fd in held:os.close(fd)

    def test_actual_census_growth_and_symlink_deny(self):
        with tempfile.TemporaryDirectory(prefix='s8-fd-census-') as directory:
            roots=[Path(directory)/name for name in ('a','b')]
            for root in roots:(root/'.git.s12-1-recovery').mkdir(parents=True)
            a=cap.probe(roots,Path(directory)/'history')[0]
            (roots[0]/'.git.s12-1-recovery'/'new').write_bytes(b'')
            b=cap.probe(roots,Path(directory)/'history')[0]
            self.assertEqual(b['required_soft'],a['required_soft']+1)
            (roots[1]/'.git.s12-1-recovery'/'unsafe').symlink_to('/dev/null')
            with self.assertRaisesRegex(c.ContractError,'FD_CENSUS_UNSAFE_OBJECT'):
                cap.probe(roots,Path(directory)/'history')


if __name__=='__main__':unittest.main()
