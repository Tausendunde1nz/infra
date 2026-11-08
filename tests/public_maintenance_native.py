"""Full Rev4 client/SSH/sudo/Host lifetime in one disposable native guest.

No production switch, Host connection, real backup or private data. Actual
Source functions, clocks, actions, fences, ACKs and cleanup are delegated.
Only expected synthetic input coordinates and explicit process interruptions
are test inputs. Calibration never confers production timing acceptance.
"""
import argparse
import base64
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0,'/source/scripts');sys.path.insert(0,'/source')
from tests import public_maintenance_fixture as f
import tu1nz_public_maintenance_diagnostics as diagnostics
client=f.client;io=f.io;ROOT=f.ROOT

# Executed solely in this guest's authenticated Host test process. Timing
# wrappers always call the actual method. Faults are actual signals/exit at a
# defined boundary, never fabricated method return values or ACKs.
HOST_TRACE=r'''
import json,math,signal
from pathlib import Path
_trace={"prepared_begin":None,"prepared_end":None,"ready":None,"owner_begin":None,
        "owner_finish":None,"service_ns":[],"terminal_begin":None,"terminal_admitted":None,
        "terminal_stopped":None,"closed":None,"fault_injected":None,"final":None}
_replacement=s.load("replacement");_io=s.load("io")
def _interrupt(label,*,fatal=False):
 assert _trace["fault_injected"] is None
 _trace["fault_injected"]=label
 if fatal:
  _save_trace()
  os._exit(72)
 os.kill(os.getpid(),signal.SIGTERM)
def _wrap(cls,name,handler):
 actual=getattr(cls,name)
 def call(*a,**kw):return handler(actual,*a,**kw)
 setattr(cls,name,call)
def _prepare(actual,*a,**kw):
 _trace["prepared_begin"]=time.monotonic_ns()
 try:return actual(*a,**kw)
 finally:_trace["prepared_end"]=time.monotonic_ns()
def _record(actual,self,kind,value):
 result=actual(self,kind,value)
 if kind=="maintenance_ready":_trace["ready"]=time.monotonic_ns()
 if kind=="recovery_terminal_stop_only_admission":_trace["terminal_admitted"]=time.monotonic_ns()
 if kind=="recovery_terminal_hold_current":_trace["terminal_stopped"]=time.monotonic_ns()
 return result
def _owner(actual,*a,**kw):
 assert _trace["owner_begin"] is None
 _trace["owner_begin"]=int(a[0].ceiling*1_000_000_000)-120_000_000_001
 return actual(*a,**kw)
def _finish(actual,*a,**kw):
 result=actual(*a,**kw);_trace["owner_finish"]=result;return result
def _service(actual,self,action,unit,**kw):
 began=time.monotonic_ns()
 try:
  result=actual(self,action,unit,**kw)
  if _case in ("recovery_F4","recovery_terminal_F4") and _route=="original" and action=="start":
   _interrupt("F4_AFTER_ACTUAL_START_NO_ACK",fatal=True)
  return result
 finally:_trace["service_ns"].append(time.monotonic_ns()-began)
def _prepared(actual,self,**kw):
 result=actual(self,**kw)
 if _case=="recovery_F1" and _route=="original" and kw.get("before_stop") and self.prepared_ready is not None:
  _interrupt("F1_READY_BEFORE_FIRST_BARRIER")
 return result
def _perform(actual,self,action,unit=None,**kw):
 if _case=="recovery_F2" and _route=="original" and action=="protected_rights_backup":
  _interrupt("F2_QUIET_BEFORE_BACKUP")
 return actual(self,action,unit,**kw)
def _publish(actual,self,candidate,target,expected):
 result=actual(self,candidate,target,expected)
 if _case=="recovery_F3" and _route=="original" and "/prepared/assets/" in candidate and not target.endswith("/blocked"):
  # Barrier paths are explicitly excluded; wait for a runtime/isolation asset.
  mapping=_replacement.prepared_asset_map(s.load("r3"))
  if any(v["target"]==target and v["source"] is not None for v in mapping.values()):
   _interrupt("F3_ACTUAL_ASSET_RENAME_BEFORE_OBSERVATION")
 return result
def _observe(actual,self,gate,**kw):
 if _case=="recovery_terminal_F4" and _route=="recovery-once" and gate=="rights":
  _interrupt("F4_RECOVERY_INTERRUPTED_BEFORE_OWNER")
 return actual(self,gate,**kw)
def _terminal(actual,*a,**kw):
 _trace["terminal_begin"]=time.monotonic_ns()
 return actual(*a,**kw)
def _close(actual,*a,**kw):
 try:return actual(*a,**kw)
 finally:_trace["closed"]=time.monotonic_ns()
def _save_trace():
 raw=json.dumps(_trace,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
 fd=os.open("/fixture-r4/trace-"+_route+".json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,"wb") as output:output.write(raw);output.flush();os.fsync(output.fileno())
 except BaseException:raise
def _effect(actual,self,name,unit=None):
 began=time.monotonic_ns()
 if name=="prepare_runtime_bundle":_trace["prepared_begin"]=began
 try:return actual(self,name,unit)
 finally:
  ended=time.monotonic_ns()
  if name=="prepare_runtime_bundle":_trace["prepared_end"]=ended
  if name in ("stop","start","recovery_stop","recovery_start"):_trace["service_ns"].append(ended-began)
_wrap(s.load("r3").Flow,"effect",_effect)
_wrap(_replacement.MaintenanceAdapter,"check_prepared_state",_prepared)
_wrap(_replacement.MaintenanceAdapter,"_perform",_perform)
_wrap(_replacement.MaintenanceAdapter,"service_action",_service)
_wrap(s.load("fs").Paths,"publish_owned_candidate",_publish)
_wrap(_io.LinkedRecords,"record",_record)
_wrap(_io.MaintenanceLinkedRecords,"begin_owner_admission",_owner)
_wrap(s.load("owner").Supervisor,"finish",_finish)
_wrap(_replacement.RecoveryAdapter,"observe",_observe)
_wrap(_replacement.RecoveryAdapter,"hold_known_new_units",_terminal)
_wrap(s.load("host").MaintenanceSessionResult,"close",_close)
'''


def bootstrap(raw,pins,inputs,case,route):
    program=client.maintenance_bootstrap_original(raw)
    # Source validates the synthetic asset bytes before loading anything. All
    # executable source bytes remain those from the reviewed checkout.
    point='s=m.Source(p["source"],p["hashes"])'
    assert program.count(point)==1
    program=program.replace(point,'m.ASSETS["runtime_inputs"]='+repr(io.sha(io.canonical(inputs)))+'\n'+point)
    selectors='s.load("host").dispatch_maintenance(s,p,w)'
    settings=''
    for key,value in pins.items():settings+='setattr(s.load("io"),'+repr(key)+','+repr(value)+')\n'
    settings+='s.load("io").ASSETS["runtime_inputs"]='+repr(io.sha(io.canonical(inputs)))+'\n'
    settings+='s.load("r3").MACHINE=s.load("entry").MACHINE='+repr(pins['MAINTENANCE_MACHINE'])+'\n'
    settings+='s.load("r3").OWNER_PLAN='+repr(pins['MAINTENANCE_OWNER_PLAN'])+'\n'
    settings+='s.load("artifact").APP='+repr((inputs['application']['commit'],inputs['application']['tree']))+'\n'
    settings+='s.load("artifact").SOURCE_MANIFEST='+repr(inputs['application']['manifest_sha256'])+'\n'
    settings+='s.load("artifact").INPUTS_SHA='+repr(io.sha(io.canonical(inputs)))+'\n'
    settings+='_case='+repr(case)+';_route='+repr(route)+'\n'
    assert program.count(selectors)==1
    return program.replace(selectors,settings+HOST_TRACE+'\ntry:\n _trace["final"]='+selectors+
        '\nfinally:\n _save_trace()\n')


def worker(case,route):
    f.f.assert_guest_isolation()
    packet=io.parse((ROOT/'packet.json').read_bytes());data=io.parse((ROOT/'fixture-pins.json').read_bytes())
    pins=data['pins'];inputs=data['inputs']
    io.ASSETS['runtime_inputs']=io.sha(io.canonical(inputs))
    source=io.Source(packet['source'],packet['hashes']);f.bind_expected(source,pins,inputs)
    payload=(ROOT/'runtime.tar.gz').read_bytes() if route=='original' else None
    client.maintenance_bootstrap_original=client.maintenance_bootstrap
    client.maintenance_bootstrap=lambda raw:bootstrap(raw,pins,inputs,case,route)
    connections=[]
    def ssh(remote):connections.append(time.monotonic_ns());return f.ssh_argv(remote)
    client.ssh_argv=ssh
    result=client.execute_maintenance(packet,source,password=f.PASSWORD,runtime_payload=payload,recover_once=route!='original')
    f.f.write(ROOT/('client-'+route+'.json'),io.canonical({'result':result,'connections':len(connections)}),0o600)
    return 0


def execute_worker(case,route):
    began=time.monotonic_ns()
    with (ROOT/('worker-'+route+'-stderr')).open('xb') as error:
        child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S','/source/tests/public_maintenance_native.py',
            '--case',case,'--worker',route],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=error)
        try:code=child.wait(timeout=600)
        except subprocess.TimeoutExpired:
            child.kill();child.wait(timeout=5)
            raise AssertionError('FULL_ENTRY_600_PROCESS_END_EXCEEDED') from None
    end=time.monotonic_ns()
    assert code==0,'CLIENT_PROCESS_NONZERO'
    value=io.parse((ROOT/('client-'+route+'.json')).read_bytes())
    assert value['connections']==1,'EXACTLY_ONE_NATIVE_SSH_REQUIRED'
    assert end-began<600_000_000_000,'FULL_ENTRY_600_PROCESS_END_EXCEEDED'
    trace=io.parse((ROOT/('trace-'+route+'.json')).read_bytes())
    return value['result'],trace,began,end


def snapshot(root):
    # Only this fixture's own original immutable custody. K6 may append its
    # marker and the one Recovery directory; no original object is replaced.
    return {str(p.relative_to(root)):(p.lstat().st_ino,p.lstat().st_mtime_ns,io.sha(p.read_bytes()))
        for p in root.rglob('*') if p.is_file() and 'recovery-once' not in p.parts and p.name!='owner-admission-intent'}


def records(route):
    root=f.CUSTODY/'public-rights-20261014-1'
    if route!='original':root=root/'recovery-once'
    rows=[io.parse(p.read_bytes()) for p in sorted((root/'operator-records').glob('[0-9]*.json'))]
    return root,rows


def measured(case,receipt,result,trace,began,end):
    route='original' if case=='original' else 'recovery-once';terminal=case=='recovery_terminal_F4'
    root,rows=records(route)
    row_values=rows
    def count(kind):return sum(r['kind']==kind for r in row_values)
    # Actual durable client records, actual filesystem owner count and actual
    # Supervisor finish must independently agree. No count is synthesized.
    intents=count('owner_object_intent');acks=count('owner_object_ack')
    assert intents==acks==(0 if terminal else 84),(intents,acks)
    actual_root=sum(p.stat().st_uid==0 for p in [f.f.WEB,*f.f.WEB.rglob('*')])
    assert actual_root==(4 if terminal else 88),'ACTUAL_OWNER_OBJECT_COUNT'
    final=trace['final'];assert final is not None
    assert final['cleanup']==[] and result['client_cleanup']==[] and final['abort']==[]
    assert final['r2_dispatch'] is False and result['r2_dispatch'] is False
    if terminal:
        assert result['status']=='HOLD' and count('recovery_terminal_hold_current')==1
        assert not (f.CUSTODY/'public-rights-20261014-1'/'owner-admission-intent').exists()
        assert trace['owner_finish'] is trace['owner_begin'] is None
        for unit in f.f.UNITS:
            row=f.f.run('/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,Job').decode()
            assert 'ActiveState=inactive' in row and 'MainPID=0' in row and 'Job=\n' in row
    else:
        expected=('RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED' if case=='original' else
            'RECOVERY_RIGHTS_OWNER_RECEIPTED_ORIGINAL_HOLD_R2_NOT_DISPATCHED')
        assert result['status']==expected and final['primary'] is None
        assert trace['owner_finish']['status']=='OWNER_COMPLETED' and trace['owner_finish']['owner_acks']==84
        assert len(trace['owner_finish']['cleanup_sha256'])==64
    ns=lambda a,b:math.ceil((b-a)/1_000_000)
    elapsed=ns(began,end);owner=ns(trace['owner_begin'],end) if trace['owner_begin'] is not None else 0
    prepare=ns(trace['prepared_begin'],trace['prepared_end']) if case=='original' else 0
    result_row={'entrypoints':['tu1nz_public_operator.execute_maintenance','tu1nz_public_operator_host.'+
        ('maintenance_session' if case=='original' else 'recovery_session')],
        'status':'HOLD_KNOWN_NEW_UNITS_STOPPED' if terminal else 'COMPLETE','cleanup_complete':True,
        'trace_sha256':io.sha(io.canonical({'trace':trace,'result':result,'began':began,'end':end,'records':rows})),
        'dimensions':{'runtime_objects':len(receipt['objects']),'archive_bytes':receipt['archive_bytes'],
            'expanded_file_bytes':receipt['expanded_file_bytes'],'lighting_objects':88,'lighting_files':82,'protected_objects':4},
        'elapsed_milliseconds':elapsed,'after_ready_milliseconds':ns(trace['ready'],end) if case=='original' else 0,
        'preparation_milliseconds':prepare,'owner_milliseconds':owner,
        'largest_service_action_milliseconds':math.ceil(max(trace['service_ns'],default=0)/1_000_000),
        'terminal_prepare_milliseconds':ns(trace['terminal_begin'],trace['terminal_admitted']) if terminal else 0,
        'terminal_stop_milliseconds':ns(trace['terminal_admitted'],trace['terminal_stopped']) if terminal else 0,
        'terminal_cleanup_milliseconds':ns(trace['terminal_stopped'],end) if terminal else 0,
        'linked_records':len(rows),'flow_records':sum(r['kind'].startswith('flow_') for r in row_values),
        'largest_record_bytes':max(len(io.canonical(r)) for r in rows),'owner_intents':intents,'owner_acks':acks}
    assert owner<=120000 and prepare<=120000 and result_row['largest_service_action_milliseconds']<=20000
    assert elapsed<600000
    return result_row


def main(case,phase):
    # Fresh guest service context; the short-lived Docker launcher is gone.
    time.sleep(1)
    timing=io.parse(Path('/native-timing.json').read_bytes()) if phase=='verification' else None
    packet,receipt,production_hashes=f.prepare(timing=timing)
    original,first_trace,first_begin,first_end=execute_worker(case,'original')
    if case=='original':result,trace,began,end=original,first_trace,first_begin,first_end
    else:
        assert original['status']=='HOLD' and first_trace['fault_injected'] is not None,'ORIGINAL_REAL_FAILURE_REQUIRED'
        original_root=f.CUSTODY/'public-rights-20261014-1';before=snapshot(original_root)
        result,trace,began,end=execute_worker(case,'recovery-once')
        assert snapshot(original_root)==before,'ORIGINAL_HISTORY_CHANGED'
        # Existing fixed entry blocks a second entry before any SSH dispatch.
        pins=io.parse((ROOT/'fixture-pins.json').read_bytes())
        io.ASSETS['runtime_inputs']=io.sha(io.canonical(pins['inputs']))
        source=io.Source(packet['source'],packet['hashes']);f.bind_expected(source,pins['pins'],pins['inputs'])
        r=source.load('r3');denied=False
        try:
            custody=client.RecoveryCustody(r,packet['binding'],boot_id=packet['baseline']['boot_id'],
                source_sha256=io.sha(io.canonical(packet['hashes'])),deadline=time.monotonic()+10)
        except BaseException as error:
            denied=getattr(error,'primary',None)=='PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_RECOVERY_ORIGINAL_ROOT_NAMES_OR_PRIOR_ENTRY'
        else:custody.close()
        assert denied and snapshot(original_root)==before,'SECOND_RECOVERY_ENTRY_NOT_DENIED'
    row=measured(case,receipt,result,trace,began,end)
    return {'schema':'TU1NZ_REV4_NATIVE_CASE_V1','case':case,'phase':phase,'green':True,
        'production_source_files':production_hashes,'fixture_source_files':packet['hashes'],
        'fixture_artifact_sha256':io.sha(io.canonical(receipt)),
        'original_failed_hold_preserved':case!='original','second_recovery_denied_before_SSH':case!='original',
        'run':row,'host_acceptance':False}


def failure_fields(error):
    return {'error_type':type(error).__name__,
        'code':getattr(error,'primary','NATIVE_FULL_ENTRY_ASSERTION'),
        'test_failure':diagnostics.capture(error)}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--case',choices=f.CASES,required=True)
    parser.add_argument('--phase',choices=('calibration','verification'),default='calibration')
    parser.add_argument('--worker',choices=('original','recovery-once'))
    args=parser.parse_args()
    if args.worker:raise SystemExit(worker(args.case,args.worker))
    # The outer CI never prints this file blindly. Only finite validated
    # metrics/errors may leave the private guest. Shutdown is fixture cleanup.
    result={'schema':'TU1NZ_REV4_NATIVE_CASE_V1','green':False,'case':args.case,'phase':args.phase,'host_acceptance':False}
    try:result=main(args.case,args.phase)
    except BaseException as error:
        result.update(failure_fields(error))
        for route in ('original','recovery-once'):
            path=ROOT/('client-'+route+'.json')
            if path.exists():result[route]=io.parse(path.read_bytes())
    finally:
        path=Path('/native-result.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:output.write(io.canonical(result));output.flush();os.fsync(output.fileno())
        subprocess.run(['/usr/bin/systemctl','--no-block','poweroff'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=True)
