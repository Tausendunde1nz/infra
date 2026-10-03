"""Integrated offline chain: real Git, backup, metadata and recovery guards.

Only systemd/nginx process boundaries are simulated. No server or provider is
contacted; no successful recovery/metadata result is substituted.
"""
import os
import subprocess
import sys
import unittest
from unittest import mock

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s12_1_r12_metadata_contract import fixture


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native Linux root + kernel guards required')
class IntegratedChainTests(unittest.TestCase):
    def test_r12_metadata_then_actual_recovery(self):
        with fixture(complete_backup=True) as f:
            historical=r.ATTEMPT_MARKER.read_bytes()
            self.assertEqual(r.reconcile_metadata(f['contract'])['safe_code'],
                             'S12_1_R12_METADATA_SEALED')
            real_run=r._run
            def host_boundary(argv, **kwargs):
                if argv[0]=='systemctl':
                    return subprocess.CompletedProcess(argv,0,
                        'LoadState=not-found\nActiveState=inactive\nSubState=dead\n','')
                if argv[0]=='nginx':
                    return subprocess.CompletedProcess(argv,0,'','')
                return real_run(argv,**kwargs)
            with mock.patch.object(r,'_run',side_effect=host_boundary):
                result=r.recover()
            self.assertTrue(result['ok'])
            self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
            for key,root in [('application',f['app']),('control',f['control'])]:
                self.assertEqual(r._identity(root),(f['index'][key]['commit'],f['index'][key]['tree']))
                self.assertFalse((root/r.RECOVERY_GIT_DIRECTORY).exists())


if __name__=='__main__':unittest.main()
