"""Real sudo -> frozen supervisor -> isolated reader -> ext4 kernel capture.

Fresh, netless owned container only. Source is mounted readonly. Substitutions
are synthetic historical identities/paths/evidence, public observations (no
provider I/O), and explicitly injected faults/low limits. All FD admission,
metadata, Git parsing, common leases/witnesses, timeout and cleanup are real.
No Host socket, production credentials, PID1 changes or historical stock.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_frozen_entry as frozen
import tu1nz_s8_history_operator as operator
import tu1nz_s8_execution_observer as observer
import tu1nz_s8_path_policy as policy
from tests import test_s8_historical_read as read_fixture


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and
    os.environ.get('container')=='docker' and os.environ.get('TU1NZ_S8_NATIVE_EXT4_ROOT')=='/proof',
    'owned native ext4 container only')
class NativeOperatorTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path('/.dockerenv').is_file())
        self.fixtures=[]
        for _ in range(2):
            fixture=read_fixture.NativeReadTests()
            fixture.setUp();self.fixtures.append(fixture)
        self.roots=[v.root for v in self.fixtures]
        self.history=self.fixtures[0].base/'history';self.history.mkdir(mode=0o700)
        self.hashes={}
        for name in observer.HISTORY_HASHES:
            raw=json.dumps({'synthetic':name},sort_keys=True).encode()+b'\n'
            (self.history/name).write_bytes(raw);(self.history/name).chmod(0o600)
            self.hashes[name]=hashlib.sha256(raw).hexdigest()
        # >1024 real held Git/evidence descriptors, not mocked capacity rows.
        for fixture in self.fixtures:
            for i in range(550):
                (fixture.real_git/('capacity-fixture-'+str(i))).write_bytes(b'synthetic\n')
        self.baseline=resource.getrlimit(resource.RLIMIT_NOFILE)

    def tearDown(self):
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),self.baseline)
        for fixture in reversed(self.fixtures):fixture.tearDown()

    def run_chain(self, mode):
        roles=list(observer.HISTORICAL_ROOTS)
        pairs={role:fixture.expected for role,fixture in zip(roles,self.fixtures)}
        paths={role:str(root) for role,root in zip(roles,self.roots)}
        source=Path(__file__).resolve().parents[1]/'scripts'
        modules={name:(source/(name+'.py')).read_bytes() for name in frozen.MODULES}
        modules['tu1nz_s8_execution_contract']+= (
            f'\nHISTORICAL_APPLICATION={pairs[roles[0]]!r}\nHISTORICAL_CONTROL={pairs[roles[1]]!r}\n').encode()
        profiles={str(key):value for key,value in policy.HISTORICAL_PROFILES.items() if key in
                  {path for fixture in self.fixtures for path in (fixture.root,fixture.root/'.git',fixture.real_git)}}
        modules['tu1nz_s8_path_policy']+=(
            f'\nHISTORICAL_PROFILES.update({{Path(k):v for k,v in {profiles!r}.items()}})\n').encode()
        modules['tu1nz_s8_execution_observer']+=(f'''
HISTORY=Path({str(self.history)!r})
HISTORY_HASHES={self.hashes!r}
HISTORICAL_ROOTS={pairs!r}
_fixture_paths={paths!r}
_native_path=Path
def Path(value):return _native_path(_fixture_paths.get(str(value),str(value)))
_real_capacity=capture_capacity
def capture_capacity(roots,history,evidence):
 return _real_capacity(tuple(_native_path(_fixture_paths[str(r)]) for r in roots),history,evidence)
''').encode()
        services={name:dict(ActiveState='active',SubState='running',NRestarts='0',NeedDaemonReload='no',
            MainPID='0',InvocationID='synthetic') for name in (*operator.PUBLIC,*operator.SEPARATE)}
        services['tu1nz-adult-commercial-s12-yoti-runtime.service']['ActiveState']='inactive'
        health={'services':services,'http':{url:dict(exit_code=0,code=code) for url,code in operator.HTTP.items()}}
        modules['tu1nz_s8_history_operator']+=(f'''
ROOTS=tuple(Path(v) for v in {[str(root) for root in self.roots]!r})
HISTORY=Path({str(self.history)!r})
OTHER_FIXED=tuple(Path(v) for v in {[str(self.history/'unused-admission'),str(self.history/'unused-anchor')]!r})
def health():return {health!r}
''').encode()
        injection=""
        if mode=='hard-denial':
            injection="resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))\n"
        elif mode in ('exhaustion','interruption'):
            injection=f'''
import tu1nz_s8_historical_kernel as kernel
_real_acquire=kernel.ReadLeases.acquire
_acquisitions=0
def injected_acquire(self,fd):
 global _acquisitions
 _real_acquire(self,fd);_acquisitions+=1
 if _acquisitions==75:raise {"OSError(24,'synthetic EMFILE')" if mode=='exhaustion' else "KeyboardInterrupt('synthetic interruption')"}
kernel.ReadLeases.acquire=injected_acquire
'''
        elif mode=='growth':
            injection=f'''
import tu1nz_s8_historical_capacity as capacity
_real_census=capacity.census
def grown_census(roots):
 result=_real_census(roots)
 from pathlib import Path
 for i in range(600):
  (Path({str(self.fixtures[0].real_git)!r})/('growth-'+str(i))).write_bytes(b'synthetic growth')
 return result
capacity.census=grown_census
'''
        entry=('import os,resource\nresource.setrlimit(resource.RLIMIT_NOFILE,(256,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))\n'
            +injection+'from tu1nz_s8_history_entry import main\nmain()\n').encode()
        reader=frozen.build(modules,entry,{**{n:hashlib.sha256(v).hexdigest() for n,v in modules.items()},
            'entry':hashlib.sha256(entry).hexdigest()}).encode()
        machine=hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()
        supervisor_entry=(f'''import json
from tu1nz_s8_history_operator import execute
result=execute({reader!r},program_sha256={hashlib.sha256(reader).hexdigest()!r},machine_sha256={machine!r})
print('S8_HISTORY_REPORT_BEGIN')
print(json.dumps(result,sort_keys=True))
print('S8_HISTORY_REPORT_END')
''').encode()
        operator_modules={n:modules[n] for n in frozen.HISTORY_OPERATOR_MODULES}
        supervisor=frozen.build_history_operator(operator_modules,supervisor_entry,{**{n:hashlib.sha256(v).hexdigest() for n,v in operator_modules.items()},
            'entry':hashlib.sha256(supervisor_entry).hexdigest()}).encode()
        # This is the exact real sudo argv/compressed isolated Python transport,
        # not a Python subprocess standing in for sudo or a permissive shell.
        result=subprocess.run(operator.sudo_command(supervisor),capture_output=True,timeout=100)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[:500])
        value=operator.parse_report(result.stdout,result.returncode)
        self.assertTrue(value['reader_started']);self.assertEqual(value['reader_launches'],1)
        self.assertTrue(value['own_protection_released'])
        self.assertEqual(value['remaining_own_group'],{'rows':[],'unknown':0})
        self.assertTrue(value['metadata_equal'] if mode!='growth' else value['metadata_equal'] is False)
        self.assertTrue(value['health_equal'])
        self.assertEqual(value['after_metadata']['target_leases'],[])
        self.assertFalse(value['slot_consumed_by_tool']);self.assertFalse(value['automatic_retry'])
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),self.baseline)
        return value

    def test_real_sudo_common_capture_low_softlimit(self):
        value=self.run_chain('success')
        self.assertEqual(value['status'],'HOST_CAPTURE_GREEN_CURRENT_INTERVAL_ONLY')
        result=value['canonical_result'];self.assertEqual(result['historical_capture'],'GREEN')
        self.assertEqual(result['history']['hashes'],self.hashes)
        fd=result['fd_capacity']
        self.assertEqual(fd['previous_soft'],256);self.assertGreater(fd['required_soft'],1100)
        self.assertEqual(fd['admitted_soft'],fd['required_soft'])
        self.assertGreater(fd['observed_common_capture_fds'],1100)
        self.assertLess(fd['observed_common_capture_high_water'],fd['required_soft'])
        self.assertEqual(fd['unchanged_hard'],value['prerequisites']['fd_hard'])
        self.assertTrue(fd['limit_restored']);self.assertTrue(fd['fd_baseline_restored'])

    def test_actual_low_hardlimit_denied_before_kernel_protection(self):
        value=self.run_chain('hard-denial')
        self.assertEqual(value['canonical_result']['historical_capture'],'RED')
        self.assertIn('FD_HARD_CAPACITY_INSUFFICIENT',repr(value['canonical_result']['primary']))
        self.assertEqual(value['canonical_result']['fd_capacity'],{})

    def test_resource_exhaustion_after_75_real_leases_has_complete_cleanup(self):
        value=self.run_chain('exhaustion')
        result=value['canonical_result'];self.assertEqual(result['historical_capture'],'RED')
        self.assertTrue(result['fd_capacity']['limit_restored']);self.assertTrue(result['fd_capacity']['fd_baseline_restored'])
        self.assertEqual(result['primary']['errno'],24)

    def test_interruption_after_75_real_leases_has_complete_cleanup(self):
        result=self.run_chain('interruption')['canonical_result']
        self.assertEqual(result['historical_capture'],'RED')
        self.assertTrue(result['fd_capacity']['limit_restored']);self.assertTrue(result['fd_capacity']['fd_baseline_restored'])
        self.assertIn('KeyboardInterrupt',repr(result['primary']))

    def test_growth_after_census_exhausts_real_budget_without_fallback(self):
        value=self.run_chain('growth');result=value['canonical_result']
        self.assertEqual(result['historical_capture'],'RED')
        self.assertEqual(result['primary']['errno'],24)
        self.assertTrue(result['fd_capacity']['limit_restored']);self.assertTrue(result['fd_capacity']['fd_baseline_restored'])
        self.assertEqual(value['status'],'INCOMPLETE_OR_RED_NO_RETRY')


if __name__=='__main__':unittest.main()
