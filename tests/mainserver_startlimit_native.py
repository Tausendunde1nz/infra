"""Public synthetic PID1 proof; no private Source, host capture or host action.

The 900-second age is fixture preparation BEFORE the measured 600-second
window. This tests only StartLimit evidence, not full maintenance timing.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,'/source/scripts')
import tu1nz_public_operator  # authenticated public io loader
import tu1nz_public_operator_io as io
import tu1nz_public_operator_observe as observe
import tu1nz_public_runtime_transition as transition

ROOT=Path('/startlimit-native')
UNITS=observe.UNITS


def run(*args,check=True):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=20,env=observe.ENV)
    assert not check or result.returncode==0, 'NATIVE_START_LIMIT_COMMAND_FAILED'
    return result


def unit(name):
    return observe.unit_rows((name,),time.monotonic()+20)[name]


def denied(call):
    try:call()
    except io.Hold:return
    raise AssertionError('NATIVE_START_LIMIT_FALSE_PERMISSION')


def wait_state(name,states,*,result=None):
    end=time.monotonic()+20
    while time.monotonic()<end:
        row=unit(name)
        if ((row['ActiveState'],row['SubState']) in states and not row['Job'] and
                (result is None or row['Result']==result)):return row
        time.sleep(.05)
    print(json.dumps({'synthetic_timeout_state':{k:row[k] for k in transition.START_LIMIT_UNIT_FIELDS}},sort_keys=True),flush=True)
    raise AssertionError('NATIVE_START_LIMIT_STATE_TIMEOUT')


def main():
    assert os.geteuid()==0 and Path('/.dockerenv').is_file() and os.environ.get('container')=='docker'
    assert Path('/proc/1/comm').read_text().strip()=='systemd'
    assert not Path('/proc/net/route').read_text().splitlines()[1:]
    assert all(p.name=='lo' or not int((p/'flags').read_text(),16)&1
               for p in Path('/sys/class/net').iterdir() if p.is_dir())
    assert run('/usr/bin/findmnt','-n','-o','VFS-OPTIONS','-T','/source').stdout.decode().split(',')[0]=='ro'
    assert not Path('/opt/tu1nz_repos').exists() and not Path('/control-source').exists()
    version=run('/usr/bin/systemctl','--version').stdout.decode().splitlines()[0]
    assert version.startswith('systemd 255 '), 'NATIVE_START_LIMIT_VERSION_OUTSIDE_PROOF'
    assert not ROOT.exists();ROOT.mkdir(mode=0o700)
    (ROOT/'fail-second').write_bytes(b'synthetic\n')
    for index,name in enumerate(UNITS):
        script=ROOT/(str(index)+'.py')
        script.write_text('import os,time\n'+
            ('os._exit(73)\n' if index==2 else
             ('if os.path.exists("/startlimit-native/fail-second"):os._exit(73)\n' if index==1 else '')+
             'while True:time.sleep(1)\n'))
        target=Path('/etc/systemd/system')/name
        assert not target.exists()
        target.write_text('[Unit]\nStartLimitIntervalSec='+('6s' if index==2 else '900s')+
            '\nStartLimitBurst=3\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -I -B '+str(script)+
            '\nRestart=on-failure\nRestartSec='+('100ms' if index==2 else '15s')+
            '\n[Install]\nWantedBy=multi-user.target\n')
        # Keep the same unit object referenced after stop. If a real target
        # were GC-unloaded, missing timestamps/InvocationID must deny proof.
        run('/usr/bin/systemctl','enable',name)
    run('/usr/bin/systemctl','daemon-reload')
    run('/usr/bin/systemctl','--job-mode=fail','start',UNITS[0])
    run('/usr/bin/systemctl','--job-mode=fail','start',UNITS[1])
    wait_state(UNITS[1],{('activating','auto-restart')})
    # Fixture construction only: stop during the 15s auto-restart wait. It
    # creates a terminal first-failure state without resetting either counter.
    run('/usr/bin/systemctl','--job-mode=fail','stop',UNITS[1])
    terminal_state=wait_state(UNITS[1],{('failed','failed'),('inactive','dead')})
    print(json.dumps({'synthetic_terminal_state':{k:terminal_state[k] for k in transition.START_LIMIT_UNIT_FIELDS}},sort_keys=True),flush=True)
    (ROOT/'fail-second').unlink()  # synthetic fault trigger only
    run('/usr/bin/systemctl','--job-mode=fail','start',UNITS[2],check=False)
    limit=wait_state(UNITS[2],{('failed','failed')})
    # PID1 can preserve the preceding exit-code Result when the limiter is
    # hit. Result alone is not a limiter/counter proof; positive NRestarts
    # must deny independently (also after its interval later expires).
    assert int(limit['NRestarts'])>0
    provider=Path('/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-255.so')
    fd=os.open(provider,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    reader=transition.ReadOnlyBus(fd,time.monotonic()+1100)
    cases=[]
    try:
        def snapshot(name):return transition.start_limit_state_read(reader,unit,name)
        early=snapshot(UNITS[0]);failed=snapshot(UNITS[1])
        assert failed['unit_state']['NRestarts']=='0' and failed['unit_state']['Result']=='exit-code'
        denied(lambda:transition.start_limit_permission(early,require_active=True))
        denied(lambda:transition.start_limit_permission(failed))
        denied(lambda:transition.start_limit_permission(snapshot(UNITS[2])))
        cases.append('RECENT_ACTIVE_TERMINAL_AND_POSITIVE_RESTART_COUNTER_DENIED')
        # A real no-op job still invalidates the passive observer. No injected
        # manager reply, condition timestamp, rate counter or callback.
        watch=transition.StartLimitObservation(reader)
        run('/usr/bin/systemctl','--job-mode=fail','start',UNITS[0])
        end=time.monotonic()+5
        while not watch.failure and time.monotonic()<end:
            try:watch.drain()
            except io.Hold:assert watch.failure
            if not watch.failure:time.sleep(.02)
        denied(watch.drain);assert watch.events>0
        watch.close();reader.start_limit_watch=None
        cases.append('REAL_FOREIGN_JOB_LATCHED')
        target=max(early['properties']['ActiveEnterTimestampMonotonic'],
                   failed['properties']['StateChangeTimestampMonotonic'])/1_000_000+900.1
        print('SYNTHETIC_900S_PREPARATION_WAIT',flush=True)
        while time.monotonic()<target:time.sleep(min(1,target-time.monotonic()))
        # No maintenance deadline is running during the fixture ageing above.
        maintenance_start=time.monotonic();maintenance_end=maintenance_start+600
        anchor=snapshot(UNITS[0]);terminal=snapshot(UNITS[1])
        assert transition.start_limit_permission(anchor,require_active=True)=='AGED_SUCCESSFUL_ACTIVE_INVOCATION'
        assert transition.start_limit_permission(terminal)=='AGED_TERMINAL_TRANSITION_AFTER_LAST_CONDITION'
        # A real reload must preserve the relevant evidence and limits.
        run('/usr/bin/systemctl','daemon-reload')
        reloaded=snapshot(UNITS[0])
        assert all(anchor[k]==reloaded[k] for k in ('properties','unit_state','manager_owner'))
        run('/usr/bin/systemctl','--job-mode=fail','stop',UNITS[0])
        wait_state(UNITS[0],{('inactive','dead')})
        stopped=snapshot(UNITS[0])
        assert transition.start_limit_permission(stopped,anchor=anchor)=='SAME_AGED_INVOCATION_NOW_SUCCESSFULLY_EMPTY'
        denied(lambda:transition.start_limit_permission(stopped))
        cases.append('REAL_900S_ACTIVE_ANCHOR_SURVIVES_RELOAD_AND_SUCCESSFUL_STOP')
        watch=transition.StartLimitObservation(reader)
        for name,old in ((UNITS[0],anchor),(UNITS[1],None)):
            start=time.monotonic();before=unit(name)
            proof=watch.bind_current_permission(name,unit,anchor=old)
            assert proof['snapshot']['properties']['StartLimitIntervalUSec']==900_000_000
            assert proof['snapshot']['properties']['StartLimitBurst']==3 and watch.remaining(name)==0
            watch.retire_for_start(name)
            run('/usr/bin/systemctl','--job-mode=fail','start',name)
            after=wait_state(name,{('active','running')})
            assert after['InvocationID']!=before['InvocationID'] and after['NRestarts']=='0'
            assert time.monotonic()-start<20 and time.monotonic()<maintenance_end
            watch.drain()  # the other unit's passive job guard is still active
        cases.append('REAL_900S_TERMINAL_AND_STOPPED_STARTS_EACH_WITHIN_20S')
        watch.close();reader.close();assert not reader.bus and not watch.slots
        elapsed=time.monotonic()-maintenance_start
        for name in UNITS:run('/usr/bin/systemctl','--job-mode=fail','stop',name)
        assert all(unit(name)['MainPID']=='0' and unit(name)['ControlPID']=='0' and not unit(name)['Job'] for name in UNITS)
        result={'schema':'TU1NZ_START_LIMIT_NATIVE_255','cases':cases,'systemd':version,
                'component_seconds':elapsed,'full_600_second_maintenance_proof':False,
                'production_data_or_services':False,'counter_or_limit_reset':False,'own_cleanup':True}
        print(json.dumps(result,sort_keys=True),flush=True)
    finally:
        reader.close();os.close(fd)


if __name__=='__main__':main()
