import errno
import unittest
from unittest.mock import Mock
import tu1nz_process_exit_evidence as m

P = {'pid': 101, 'start': 123, 'pgrp': 100, 'state': 'S'}

class Tests(unittest.TestCase):
    def test_esrch_confirmed_twice(self):
        read=Mock(side_effect=[ProcessLookupError(errno.ESRCH,'gone'),FileNotFoundError(errno.ENOENT,'gone')])
        self.assertTrue(m.stopped(P,read,Mock(side_effect=ProcessLookupError(errno.ESRCH,'gone'))))
        self.assertEqual(read.call_count,2)
    def test_esrch_but_still_alive(self):
        self.assertFalse(m.stopped(P,Mock(side_effect=ProcessLookupError(errno.ESRCH,'gone')),Mock(return_value=None)))
    def test_reused_pid_rejected(self):
        with self.assertRaises(ValueError):m.stopped(P,lambda _:dict(P,start=999))
    def test_live_and_zombie(self):
        self.assertFalse(m.stopped(P,lambda _:P))
        self.assertTrue(m.stopped(P,lambda _:dict(P,state='Z')))
    def test_permission_not_swallowed(self):
        with self.assertRaises(PermissionError):m.stopped(P,Mock(side_effect=PermissionError()))
    def test_probe_error_not_swallowed(self):
        with self.assertRaises(PermissionError):m.stopped(P,Mock(side_effect=FileNotFoundError(errno.ENOENT,'gone')),Mock(side_effect=PermissionError()))
    def test_reappears_after_esrch(self):
        read=Mock(side_effect=[FileNotFoundError(errno.ENOENT,'gone'),dict(P,start=999)])
        self.assertFalse(m.stopped(P,read,Mock(side_effect=ProcessLookupError(errno.ESRCH,'gone'))))
    def test_group_member_running(self):
        self.assertFalse(m.group_stopped(100,lambda:[101],lambda _:P))
        self.assertTrue(m.group_stopped(100,lambda:[101],lambda _:dict(P,state='Z')))
    def test_timeout(self):
        ticks=iter([0,.01,.02,3])
        with self.assertRaises(TimeoutError):m.await_stopped([P],clock=lambda:next(ticks),sleep=lambda _:None,check=lambda _:False)
    def test_cleanup_error(self):
        with self.assertRaises(OSError):m.await_stopped([P],check=Mock(side_effect=OSError('failure')))
    def test_two_observations(self):
        check=Mock(return_value=True)
        m.await_stopped([P],sleep=lambda _:None,check=check,group_check=lambda _:True)
        self.assertEqual(check.call_count,2)

if __name__=='__main__':unittest.main()
