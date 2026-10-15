"""Synthetic network-none PID1 sequence fixture, never a production operator.

Real systemd stop/children/condition/reexec and persistent client journal;
remaining production admission witnesses are expressly synthetic test inputs.
The unchanged helper/native fixture and original R2 CI run separately as well.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

spec=importlib.util.spec_from_file_location('bootstrap_native_component','/source/scripts/tu1nz_public_bootstrap_r3.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
ETC=Path('/etc/systemd/system');BOOT=Path(m.BOOT);BINDING='c'*64
PROGRAM="import os,time;os.fork();time.sleep(300)"

def cmd(*args,check=True):
    r=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if check and r.returncode:raise RuntimeError(json.dumps({'argv':args[:2],'exit':r.returncode,'stderr':r.stderr[-500:]}))
    return r
def system(*args,check=True):return cmd('/usr/bin/systemctl',*args,check=check)
def put(p,raw,mode=0o644):
    p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def running(unit):return system('is-active','--quiet',unit,check=False).returncode==0
def empty(unit):
    cg=system('show',unit,'--property=ControlGroup','--value').stdout.strip()
    if not cg:return True
    root=Path('/sys/fs/cgroup')/cg.lstrip('/')
    return not root.exists() or all(not p.read_text().strip() for p in root.rglob('cgroup.procs'))

class FixtureAdapter:
    """Synthetic receipt issuer, NOT an actual Host/TCB/owner admission adapter."""
    def __init__(self,work,scenario):
        self.work=work;self.scenario=scenario;self.calls=[];self.backup=None;self.foreign=None
    def observe(self,phase,*,deadline):
        assert time.monotonic()<=deadline
        facts=set(m.REQUIRED[phase])
        if phase in ('quiet','staging_ready','staging','backup','restore','probes','install'):
            if any(running(u) or not empty(u) for u in m.UNITS):facts.discard('three_cgroups_empty')
        if phase=='quiet' and self.foreign is not None and self.foreign.poll() is None:
            facts.discard('no_unknown_authority')
        if phase=='barriers':
            if not all((ETC/(u+'.d')/m.BARRIER).read_bytes()==m.BARRIER_BYTES for u in m.UNITS):facts.clear()
        if phase=='backup' and self.scenario in ('backup','foreign_return','return_release','return_crash_release'):facts.discard('independent_readback')
        if phase=='restore' and self.scenario=='restore':facts.discard('isolated_metadata_content_restore_and_return_rehearsal')
        if phase=='probes' and self.scenario=='probe':facts.discard('installed_kernel_systemd_proof')
        if phase=='return_before_install' and self.scenario=='foreign_return':facts.clear()
        if phase.startswith(('return_release:','release:')):
            unit=phase.split(':',1)[1];index=m.UNITS.index(unit)
            if (ETC/(unit+'.d')/m.BARRIER).exists():facts.clear()
            if any(not (ETC/(u+'.d')/m.BARRIER).exists() for u in m.UNITS[index+1:]):facts.clear()
        if phase=='return_config' and any(self.work.glob('synthetic-install-*')):facts.clear()
        if phase.startswith('return_state:'):
            unit=phase.split(':',1)[1]
            if running(unit):facts.add('currently_active_requires_single_return_stop')
            elif empty(unit):facts.add('currently_stopped_cgroup_empty')
        if phase=='started:'+m.UNITS[0] and self.scenario=='partial_start_return':facts.clear()
        return m.Observation(m.TX,BINDING,phase,frozenset(facts),time.monotonic())
    def perform(self,action,unit,*,deadline):
        assert time.monotonic()<deadline
        self.calls.append((action,unit))
        if action in ('create_persistent_barriers','establish_return_barriers'):
            BOOT.mkdir(parents=True,exist_ok=True);BOOT.chmod(0o700)
            for u in m.UNITS:
                p=ETC/(u+'.d')/m.BARRIER
                if not p.exists():put(p,m.BARRIER_BYTES)
            system('daemon-reload')
        elif action in ('stop','return_stop'):
            if action=='return_stop':assert running(unit),'DUPLICATE_RETURN_STOP'
            if self.scenario=='incomplete' and action=='stop':
                return {'outcome':'CONFIRMED','action':action,'unit':unit,'cgroup_empty':False,'no_job':False}
            system('stop',unit)
            if self.scenario=='interrupted' and action=='stop':raise KeyboardInterrupt()
            return {'outcome':'CONFIRMED','action':action,'unit':unit,'cgroup_empty':empty(unit),'no_job':True}
        elif action=='create_sealed_staging':(self.work/'staging').mkdir(mode=0o700)
        elif action=='protected_rights_backup':
            self.backup={u:(ETC/u).read_bytes() for u in m.UNITS}
            for u,raw in self.backup.items():put(self.work/'backup'/u,raw,0o600)
            assert all((self.work/'backup'/u).read_bytes()==raw for u,raw in self.backup.items())
        elif action=='isolated_restore_rehearsal':
            for u,raw in self.backup.items():
                put(self.work/'restore'/u,(self.work/'backup'/u).read_bytes(),0o600)
                assert (self.work/'restore'/u).read_bytes()==raw
        elif action=='bounded_synthetic_probes':
            # Real helper kernel/profile probes are the unchanged next native
            # fixture; this ordering fixture does not claim that Host proof.
            pass
        elif action=='install_four_artifacts':
            for i in range(4):put(self.work/('synthetic-install-'+str(i)),b'SYNTHETIC_NOT_RUNTIME',0o600)
            if self.scenario=='partial_install':raise OSError('SYNTHETIC_INSTALL_UNKNOWN')
        elif action=='return_old_configuration':
            # Configuration restoration does NOT implicitly release start barriers.
            if unit=='return_after_install':
                assert self.backup and all((ETC/u).read_bytes()==raw for u,raw in self.backup.items())
                for i in range(4):
                    p=self.work/('synthetic-install-'+str(i))
                    assert p.read_bytes()==b'SYNTHETIC_NOT_RUNTIME'
                    p.rename(self.work/('quarantined-install-'+str(i)))
        elif action in ('quarantine_own_barrier','quarantine_own_return_barrier'):
            if self.scenario=='return_release':raise OSError('SYNTHETIC_RETURN_RELEASE_FAILURE')
            p=ETC/(unit+'.d')/m.BARRIER
            assert p.read_bytes()==m.BARRIER_BYTES
            target=self.work/('quarantined-'+unit)
            if target.exists():target=self.work/('return-quarantined-'+unit)
            p.rename(target)
            system('daemon-reload')
        elif action in ('start','start_old'):
            system('start',unit)
            if self.scenario=='crash_release' and action=='start':raise KeyboardInterrupt()
            if self.scenario=='return_crash_release' and action=='start_old':raise KeyboardInterrupt()
        elif action=='supervised_owner_transaction':
            assert all(running(u) for u in m.UNITS)
            # Component84/leases/owner enforcement is not replaced by this
            # ordering fixture; it has no actual production object plan.
        else:raise AssertionError('UNEXPECTED_SYNTHETIC_ACTION')
        return {'outcome':'CONFIRMED','action':action,'unit':unit}

def setup():
    assert os.geteuid()==0 and os.environ.get('container')=='docker' and Path('/.dockerenv').exists()
    assert Path('/proc/1/comm').read_text().strip()=='systemd'
    assert cmd('/usr/bin/findmnt','-n','-o','OPTIONS','--target','/source').stdout.strip().startswith('ro')
    for i,u in enumerate(m.UNITS):
        unit='[Unit]\n'
        if i:unit+='Requires='+m.UNITS[0]+'\nAfter='+m.UNITS[0]+'\n'
        unit+='[Service]\nType=simple\nExecStart=/usr/bin/python3 -c "'+PROGRAM+'"\nKillMode=control-group\nRestart=on-failure\nRestartSec=1s\nTimeoutStopSec=2s\n'
        put(ETC/u,unit.encode())
        (ETC/(u+'.d')).mkdir()
    system('daemon-reload')
    for u in m.UNITS:system('start',u)
    assert all(running(u) for u in m.UNITS)

def cleanup_fixture():
    # ONLY this newly created synthetic guest's exact fixture units/files.
    for u in m.STOP:system('stop',u)
    for u in m.UNITS:
        p=ETC/(u+'.d')/m.BARRIER
        if p.exists():assert p.read_bytes()==m.BARRIER_BYTES;p.unlink()
        (ETC/(u+'.d')).rmdir();(ETC/u).unlink()
    system('daemon-reload')

def main():
    results=[]
    for scenario in ('success','incomplete','remaining_writer','backup','restore','probe','foreign_return',
                     'interrupted','partial_install','return_release','crash_release','return_crash_release','partial_start_return'):
        setup()
        with tempfile.TemporaryDirectory(prefix='r3-native-journal-',dir='/etc') as temp:
            parent=Path(temp);parent.chmod(0o700);work=parent/'work';work.mkdir(mode=0o700)
            # Explicit synthetic guest custody substitution; production requires
            # the fixed reviewed Mac parent and cannot select this fixture path.
            m.CUSTODY_PARENT=parent
            j=m.Journal(parent,BINDING);adapter=FixtureAdapter(work,scenario);flow=m.Flow(adapter,j)
            if scenario=='remaining_writer':
                # An actually live synthetic descendant outside the3 service
                # cgroups, retained by this fixture (never stopped by Flow).
                adapter.foreign=subprocess.Popen(['/usr/bin/python3','-c',
                    "import time;f=open(__import__('sys').argv[1],'wb');f.write(b'SYNTHETIC');f.flush();time.sleep(120)",str(work/'foreign-writer')])
            try:
                if scenario=='success':
                    assert flow.forward()=='RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED'
                    assert all(running(u) for u in m.UNITS)
                else:
                    try:flow.forward();raise AssertionError('FAILURE_NOT_DENIED')
                    except (m.Denied,KeyboardInterrupt):pass
                    assert flow.hold
                    if scenario not in ('partial_install','crash_release','partial_start_return'):assert not any(a=='install_four_artifacts' for a,u in adapter.calls)
                    if scenario=='partial_start_return':
                        assert running(m.UNITS[0]) and all(not running(u) for u in m.UNITS[1:])
                        assert flow.return_old()=='OLD_OPERATION_RESTORED_SECURITY_RED'
                        assert [u for a,u in adapter.calls if a=='return_stop']==[m.UNITS[0]]
                        assert all(running(u) for u in m.UNITS)
                    if scenario in ('backup','restore','probe','foreign_return','partial_install','return_release','return_crash_release'):
                        # Persistent condition refuses both manual and dependency
                        # activation, including after manager re-execution.
                        system('daemon-reexec');system('start',m.UNITS[1],check=False)
                        assert all(not running(u) and empty(u) for u in m.UNITS)
                        if scenario in ('foreign_return','return_release'):
                            try:flow.return_old();raise AssertionError('UNSAFE_RETURN')
                            except m.Denied:pass
                            assert all(not running(u) for u in m.UNITS)
                        elif scenario=='return_crash_release':
                            try:flow.return_old();raise AssertionError('RETURN_INTERRUPT_NOT_DENIED')
                            except m.Denied:pass
                            system('daemon-reexec')
                            for u in m.UNITS[1:]:system('start',u,check=False)
                            assert running(m.UNITS[0]) and all(not running(u) and empty(u) for u in m.UNITS[1:])
                        else:
                            assert flow.return_old()=='OLD_OPERATION_RESTORED_SECURITY_RED'
                            assert all(running(u) for u in m.UNITS)
                    elif scenario!='partial_start_return':
                        assert not any(a=='start_old' for a,u in adapter.calls)
                        if adapter.foreign is not None:assert adapter.foreign.poll() is None
                        if scenario=='crash_release':
                            system('daemon-reexec')
                            for u in m.UNITS[1:]:system('start',u,check=False)
                            assert all(not running(u) and empty(u) for u in m.UNITS[1:])
                try:m.Journal(parent,'d'*64);raise AssertionError('REPLAY')
                except m.Denied:pass
                results.append({'scenario':scenario,'result':'GREEN','actual_systemd':True,
                                'host_acceptance':False,'R2_dispatch':False})
            finally:
                if adapter.foreign is not None:
                    adapter.foreign.terminate();adapter.foreign.wait(timeout=5)
                j.close()
        cleanup_fixture()
    print(json.dumps({'schema':'TU1NZ_PUBLIC_BOOTSTRAP_R3_NATIVE_FIXTURE_V1','network':'none',
        'source_readonly':True,'synthetic_only':True,'manager_reexec_not_Host_reboot':True,
        'actual_production_TCB_backup_owner_and_R2_proof':False,'results':results},sort_keys=True))

if __name__=='__main__':main()
