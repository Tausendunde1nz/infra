"""Exact operator-path negatives; no Host/lease/provider I/O in adapter cases."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_history_operator as op
import tu1nz_s8_execution_contract as c


class OperatorTests(unittest.TestCase):
    def exercise(self,*,capture='GREEN',rc=0,metadata_changed=False,health_changed=False,
                 alive=False,timeout=False,interrupt=False,leases=False,hard_denied=False,post_failure=False):
        program=b'synthetic-history-program';fake=Mock(pid=4000,returncode=rc)
        fake.poll.return_value=None if alive else rc
        result=dict(schema='TU1NZ_S8_HISTORICAL_READ_R5_DELTA_V1',historical_capture=capture,
                    fd_capacity=dict(limit_restored=True,fd_baseline_restored=True))
        fake.communicate.return_value=(json.dumps(result).encode(),b'')
        if timeout:fake.communicate.side_effect=subprocess.TimeoutExpired('owned',55)
        if interrupt:fake.communicate.side_effect=KeyboardInterrupt()
        pre=dict(objects=7067,target_leases=[])
        post=dict(objects=7067,target_leases=[dict(pid=9)] if leases else [])
        health=dict(services={'synthetic':dict(InvocationID='before')},http={'synthetic':200})
        health2=dict(services={'synthetic':dict(InvocationID='after' if health_changed else 'before')},http={'synthetic':200})
        meta=[(pre,{'x':1}),(post,{'x':2 if metadata_changed else 1})]
        if post_failure:meta[1]=OSError('synthetic post read unavailable')
        with patch.object(op,'prerequisites',return_value=dict(fd_soft=1024,fd_hard=10000)), \
             patch.object(op,'health',side_effect=[health,health2]) as observe, \
             patch.object(op,'require_public_health'),patch.object(op,'metadata',side_effect=meta), \
             patch.object(op,'probe',side_effect=c.ContractError('S8_EXECUTION_FD_HARD_CAPACITY_INSUFFICIENT')
                if hard_denied else None,return_value=({'required_soft':7105},{})), \
             patch.object(op,'process_rows',return_value=dict(rows=[dict(pid=4001)] if alive else [],unknown=0)), \
             patch.object(op.subprocess,'Popen',return_value=fake) as launch:
            out=op.execute(program,program_sha256=hashlib.sha256(program).hexdigest(),machine_sha256='a'*64)
        self.assertEqual(launch.call_count,0 if hard_denied else 1)
        if not hard_denied:
            self.assertEqual(launch.call_args.args[0],['/usr/bin/timeout','--signal=TERM','--kill-after=5s','40s',
                                                     '/usr/bin/python3','-I','-B','-S','-'])
            self.assertEqual(fake.communicate.call_count,1)
            self.assertEqual(fake.communicate.call_args.kwargs['input'],program)
            self.assertTrue(launch.call_args.kwargs['close_fds'])
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            self.assertFalse(fake.kill.called);self.assertFalse(fake.terminate.called)
            for stream in (fake.stdin,fake.stdout,fake.stderr):stream.close.assert_called_once()
            self.assertEqual(observe.call_count,2)
        self.assertFalse(out['automatic_retry']);self.assertFalse(out['slot_consumed_by_tool'])
        return out

    def test_full_gate_green_only_after_cleanup(self):
        out=self.exercise();self.assertEqual(out['status'],'HOST_CAPTURE_GREEN_CURRENT_INTERVAL_ONLY')

    def test_actual_small_soft_large_hard_not_blocked_by_old_fixed_gate(self):
        self.assertEqual(self.exercise()['reader_launches'],1)

    def test_hard_denies_before_any_child(self):
        out=self.exercise(hard_denied=True);self.assertFalse(out['reader_started'])
        self.assertIn('FD_HARD_CAPACITY_INSUFFICIENT',out['primary']['code'])

    def test_canonical_red_no_partial_acceptance(self):
        self.assertEqual(self.exercise(capture='RED',rc=2)['primary']['code'],'CANONICAL_HISTORY_RED')

    def test_output_or_noncanonical_exit_unknown(self):
        self.assertEqual(self.exercise(rc=124)['primary']['code'],'CANONICAL_OUTCOME_UNCERTAIN')

    def test_inconsistent_capture_exit_denied(self):
        self.assertEqual(self.exercise(capture='GREEN',rc=2)['primary']['code'],'CANONICAL_ENVELOPE_RED')

    def test_lease_left_no_foreign_signal(self):
        self.assertEqual(self.exercise(leases=True)['primary']['code'],'CLEANUP_UNPROVEN')

    def test_changed_metadata_and_invocation_remain_red(self):
        self.assertEqual(self.exercise(metadata_changed=True)['primary']['code'],'POST_METADATA_CHANGED')
        out=self.exercise(health_changed=True)
        self.assertEqual(out['primary']['code'],'POST_SERVICE_OR_HTTP_CHANGED')
        self.assertIn('synthetic',out['service_deltas'])

    def test_timeout_or_interruption_still_attempts_all_postchecks(self):
        for option in ('timeout','interrupt'):
            out=self.exercise(alive=True,**{option:True})
            self.assertFalse(out['own_protection_released'])
            self.assertIn('after_health',out)
            self.assertEqual(out['reader_launches'],1)
            self.assertEqual(out['status'],'INCOMPLETE_OR_RED_NO_RETRY')

    def test_failed_post_metadata_does_not_skip_health_or_close(self):
        out=self.exercise(post_failure=True)
        self.assertIn('after_health',out);self.assertTrue(out['cleanup'])
        self.assertFalse(out['own_protection_released'])

    def test_wrong_program_before_any_action(self):
        with patch.object(op,'prerequisites') as prerequisites,patch.object(op.subprocess,'Popen') as launch:
            out=op.execute(b'wrong',program_sha256='a'*64,machine_sha256='b'*64)
        prerequisites.assert_not_called();launch.assert_not_called()
        self.assertFalse(out['reader_started'])

    def test_command_only_sudo_exact_isolated_stdin_transport(self):
        argv=op.sudo_command(b'print("synthetic")')
        self.assertEqual(argv[:3],['/usr/bin/sudo','-k','-p'])
        self.assertEqual(argv[5:10],['/usr/bin/python3','-I','-B','-S','-c'])
        self.assertNotIn('-v',argv);self.assertNotIn('-K',argv)
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',argv[-1]],capture_output=True,check=True)
        self.assertEqual(result.stdout,b'synthetic\n')

    def test_ambiguous_protocol_never_retry(self):
        data=b'S8_HISTORY_REPORT_BEGIN\n{"status":"GREEN"}\nS8_HISTORY_REPORT_END\n'
        self.assertEqual(op.parse_report(data,0),{'status':'GREEN'})
        for raw,code in ((data+data,0),(data,255),(b'partial',0),(b'x'*(4*1024*1024+1),0)):
            self.assertEqual(op.parse_report(raw,code)['cleanup'],'UNKNOWN')


if __name__=='__main__':unittest.main()
