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
import json,math,re,signal,sys
from pathlib import Path
_trace={"prepared_begin":None,"prepared_end":None,"ready":None,"owner_begin":None,
        "owner_finish":None,"service_ns":[],"terminal_begin":None,"terminal_admitted":None,
        "terminal_stopped":None,"closed":None,"fault_injected":None,"final":None,
        "start_limit_failure":None,"r5_finish_begin":None,"r5_finish_returned":False}
_replacement=s.load("replacement");_io=s.load("io")
# Error-only projection of the values already compared. No extra manager,
# filesystem or reference read; the actual verdict/exception is unchanged.
_actual_start_limit_permission=_replacement.start_limit_permission
def _start_limit_permission(current,*,anchor=None,require_active=False):
 try:return _actual_start_limit_permission(current,anchor=anchor,require_active=require_active)
 except _io.Hold as error:
  if (error.primary=="PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_START_LIMIT_STATE_NOT_ELIGIBLE" and
      _trace["start_limit_failure"] is None):
   try:
    state=current["unit_state"]
    checks={"type_simple":state["Type"]=="simple","restarts_zero":state["NRestarts"]=="0",
     "control_pid_zero":state["ControlPID"]=="0","job_empty":not state["Job"],
     "result_not_limit_hit":state["Result"]!="start-limit-hit",
     "invocation_id_valid":bool(re.fullmatch("[0-9a-f]{32}",state["InvocationID"])),
     "active_running_pid":state["ActiveState"]=="active" and state["SubState"]=="running" and
        state["MainPID"].isdecimal() and int(state["MainPID"])>0,
     "empty_terminal_pid":(state["ActiveState"],state["SubState"]) in
        (("inactive","dead"),("failed","failed")) and state["MainPID"]=="0"}
    caller=sys._getframe(1).f_code.co_name
    callers=("pre_stop","check_prepared_state","bind_current_permission","remaining",
             "recover_state","start_limit_permission")
    units=_replacement.UNITS
    _trace["start_limit_failure"]={"checkpoint":"START_LIMIT_STATE_NOT_ELIGIBLE",
     "caller":caller if caller in callers else "OTHER",
     "unit":("S7","S8","WMS")[units.index(current["unit"])] if current["unit"] in units else "OTHER",
     "require_active":require_active,"anchor_present":anchor is not None,"checks":checks}
   except Exception:pass  # an unavailable diagnostic never replaces the real failure
  raise
_replacement.start_limit_permission=_start_limit_permission
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
def _r5_finish(actual,self,phase,**kw):
 if phase!="r5_finish":return actual(self,phase,**kw)
 assert _trace["r5_finish_begin"] is None
 _trace["r5_finish_begin"]=time.monotonic_ns()
 result=actual(self,phase,**kw);_trace["r5_finish_returned"]=True
 return result
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
_wrap(s.load("r5_completion")._R5AdapterFinish,"_observe",_r5_finish)
'''


F1_HOST_TRACE=r'''
# Installed only for recovery_F1/recovery-once. No extra reads, ACKs, polling
# or per-object output. SELF CPU excludes child/systemd work. ACK wait is an
# inclusive part of phase wall time, including failed receive attempts.
_f1={"phases":{},"active":None,"owner_deadline_ns":None,"cap_delay_ns":None,
     "close_entered":False,"close_returned":False,"in_close":False,
     "finish_entered":False,"finish_returned":False,
     "final_send_started":False,"final_send_completed":False,
     "first_close_error":None,"journal_wire":None,"stage":"session_close",
     "journal_ack":{"ack_calls":0,"ack_returns":0,"ack_wait_ns":0}}
def _f1_clock():return (time.monotonic_ns(),time.process_time_ns())
def _f1_end(outcome,at=None):
 name=_f1["active"]
 if name is not None:
  row=_f1["phases"][name];row["end"]=at or _f1_clock();row["outcome"]=outcome
  _f1["active"]=None
def _f1_begin(name,at=None):
 if name not in _f1["phases"]:
  _f1["phases"][name]={"begin":at or _f1_clock(),"end":None,"outcome":"OPEN",
    "ack_calls":0,"ack_returns":0,"ack_wait_ns":0}
  _f1["active"]=name
def _f1_abort():
 if _f1["active"]!="abort_cleanup":
  at=_f1_clock()
  if _f1["active"] is None and "apply" in _f1["phases"]:
   at=_f1["phases"]["apply"]["end"] or at
  _f1_end("INTERRUPTED",at);_f1_begin("abort_cleanup",at)
def _f1_error(error=None,code=None):
 if _f1["in_close"] and _f1["first_close_error"] is None:
  _f1["first_close_error"]={"stage":_f1["stage"],
   "kind":"EXCEPTION" if error is not None else "CLEANUP_CODE",
   "type":type(error).__name__ if error is not None else "UNKNOWN",
   "code":getattr(error,"primary",None) if error is not None else code,
   "fault":s.load("host").source_fault_location(error) if error is not None else None}
def _f1_note(fn,*a):
 try:return fn(*a)
 except Exception:pass # measurement cannot replace a real verdict/exception
def _f1_cap(actual,self,deadline):
 if type(self) is _io.RecoveryLinkedRecords and _f1["owner_deadline_ns"] is None:
  at=_f1_clock();anchor=int(deadline*1_000_000_000)-120_000_000_000
  _f1["owner_deadline_ns"]=int(deadline*1_000_000_000)
  _f1["cap_delay_ns"]=at[0]-anchor
  # Wall starts at the actual deadline's anchor; SELF CPU is sampled at cap
  # entry. cap_delay_ns discloses the small interval before that CPU sample.
  _f1_note(_f1_begin,"admission",(anchor,at[1]))
 return actual(self,deadline)
def _f1_observe(actual,self,phase,**kw):
 try:return actual(self,phase,**kw)
 except BaseException:
  if phase=="owner_ready" and _f1["active"]=="admission":_f1_note(_f1_abort)
  raise
def _f1_apply(actual,*a,**kw):
 at=_f1_clock();_f1_note(_f1_end,"COMPLETE",at);_f1_note(_f1_begin,"apply",at)
 try:result=actual(*a,**kw)
 except BaseException:
  _f1_note(_f1_abort);raise
 else:
  _f1_note(_f1_end,"COMPLETE");return result
def _f1_finish(actual,*a,**kw):
 _f1["finish_entered"]=True;_f1_note(_f1_begin,"finish_cleanup")
 try:result=actual(*a,**kw)
 except BaseException:
  _f1_note(_f1_abort);raise
 else:
  _f1["finish_returned"]=True;return result
def _f1_record(actual,self,kind,value):
 prior=_f1["journal_wire"];stage=_f1["stage"];_f1["journal_wire"]=self.wire
 if _f1["in_close"]:_f1["stage"]="journal_record"
 try:return actual(self,kind,value)
 except BaseException as error:
  _f1_note(_f1_error,error);raise
 finally:_f1["journal_wire"]=prior;_f1["stage"]=stage
def _f1_receive(actual,self):
 if self is not _f1["journal_wire"]:return actual(self)
 phase=_f1["phases"].get(_f1["active"])
 rows=[_f1["journal_ack"]]+([phase] if phase is not None else [])
 for row in rows:row["ack_calls"]+=1
 try:
  began=time.monotonic_ns()
  try:result=actual(self)
  finally:elapsed=time.monotonic_ns()-began
 except BaseException as error:
  _f1_note(_f1_error,error);raise
 else:
  for row in rows:row["ack_returns"]+=1
  return result
 finally:
  for row in rows:row["ack_wait_ns"]+=elapsed
def _f1_send(actual,self,value):
 final=_f1["in_close"] and type(value) is dict and value.get("type")=="final"
 if final:_f1["final_send_started"]=True
 prior=_f1["stage"]
 if final:_f1["stage"]="final_send"
 try:result=actual(self,value)
 except BaseException as error:
  _f1_note(_f1_error,error);raise
 else:
  if final:_f1["final_send_completed"]=True
  return result
 finally:_f1["stage"]=prior
def _f1_cleanup(actual,*a,**kw):
 prior=_f1["stage"];_f1["stage"]="resource_cleanup"
 try:result=actual(*a,**kw)
 except BaseException as error:
  _f1_note(_f1_error,error);raise
 else:
  if type(result) is list and result:_f1_note(_f1_error,None,result[0])
  return result
 finally:_f1["stage"]=prior
def _f1_owner_close(actual,*a,**kw):
 # Also separate an Owner's own failure cleanup inside apply/admission,
 # before the outer session close is reached. Normal finish owns its cleanup.
 if not _f1["finish_entered"] and _f1["active"] in ("admission","apply"):
  _f1_note(_f1_abort)
 return _f1_cleanup(actual,*a,**kw)
def _f1_close(actual,*a,**kw):
 _f1["close_entered"]=True;_f1["in_close"]=True
 _f1["owner_remaining_at_close_ns"]=(None if _f1["owner_deadline_ns"] is None else
     _f1["owner_deadline_ns"]-time.monotonic_ns())
 if not _f1["finish_returned"]:_f1_note(_f1_abort)
 # Catch failed require guards even when cleanup catches them internally.
 # Installed only during close; other swallowed errors can first become
 # observable as returned cleanup codes. This is the FIRST OBSERVED error.
 require=_io.require
 def observed_require(*args,**kwargs):
  try:return require(*args,**kwargs)
  except BaseException as error:
   _f1_note(_f1_error,error);raise
 _io.require=observed_require
 try:result=actual(*a,**kw)
 except BaseException as error:
  _f1_note(_f1_error,error);_f1_note(_f1_end,"INTERRUPTED");raise
 else:
  _f1["close_returned"]=True;_f1_note(_f1_end,"COMPLETE");return result
 finally:_io.require=require;_f1["in_close"]=False
def _f1_report():
 phases={}
 for name in ("admission","apply","finish_cleanup","abort_cleanup"):
  row=_f1["phases"].get(name)
  phases[name]={"outcome":"NOT_ENTERED","wall_ns":"UNKNOWN","cpu_ns":"UNKNOWN",
   "ack_calls":"UNKNOWN","ack_returns":"UNKNOWN","ack_wait_ns":"UNKNOWN"}
  if row is not None:
   phases[name].update({k:row[k] for k in ("outcome","ack_calls","ack_returns","ack_wait_ns")})
   if row["end"] is not None:
    phases[name].update(wall_ns=row["end"][0]-row["begin"][0],cpu_ns=row["end"][1]-row["begin"][1])
 return {"schema":"TU1NZ_F1_OWNER_PHASES_V1","phases":phases,
  "journal_ack":dict(_f1["journal_ack"]),
  "cap_delay_ns":_f1["cap_delay_ns"],
  "owner_remaining_at_close_ns":_f1.get("owner_remaining_at_close_ns"),
  **{k:_f1[k] for k in ("close_entered","close_returned","finish_entered","finish_returned",
    "final_send_started","final_send_completed","first_close_error")}}
_wrap(_io.LinkedRecords,"cap",_f1_cap)
_wrap(_replacement.MaintenanceAdapter,"_observe",_f1_observe)
_wrap(s.load("owner").Supervisor,"apply",_f1_apply)
_wrap(s.load("owner").Supervisor,"finish",_f1_finish)
_wrap(s.load("owner").Supervisor,"close",_f1_owner_close)
_wrap(_io.LinkedRecords,"record",_f1_record)
_wrap(_io.Wire,"receive",_f1_receive)
_wrap(_io.Wire,"send",_f1_send)
_wrap(_replacement.RecoveryAdapter,"close",_f1_cleanup)
_wrap(s.load("fs").Paths,"close",_f1_cleanup)
_wrap(s.load("host").MaintenanceSessionResult,"close",_f1_close)
_f1_save_trace=_save_trace
def _save_trace():
 _trace["f1_owner_profile"]=_f1_note(_f1_report)
 return _f1_save_trace()
'''


def bootstrap(raw,pins,inputs,case,route,*,legacy_sha):
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
    settings+='s.load("observe").LEGACY_CONTEXTS_SHA='+repr(legacy_sha)+'\n'
    settings+='_case='+repr(case)+';_route='+repr(route)+'\n'
    assert program.count(selectors)==1
    profile=''  # historical Owner profiler is not part of independent R5
    return program.replace(selectors,settings+HOST_TRACE+profile+'\ntry:\n _trace["final"]='+selectors+
        '\nfinally:\n _save_trace()\n')


def execute_with_transport_observation(packet, source, **kwargs):
    # F1-only diagnostic wrappers. Keep the real result, exception, transport
    # lifecycle and all deadlines. Successful per-object operations add no work.
    observed = {}; cleanup = {}; transport = [None]
    actual_init = client.MaintenanceTransport.__init__
    actual_serve = client.Client.serve
    actual_receipt = client.maintenance_cleanup_receipt
    def initialized(self, *args, **kw):
        result = actual_init(self, *args, **kw)
        transport[0] = self
        return result
    def served(self):
        try: return actual_serve(self)
        except BaseException as error:
            try: observed.update(diagnostics.capture_transport(error, self, transport[0], time.monotonic_ns()))
            except Exception: pass  # a missing diagnostic cannot replace the original error
            raise
    def receipted(parent, identity, receipt, **kw):
        digest = actual_receipt(parent, identity, receipt, **kw)
        try: cleanup.update(digest=digest, receipt=io.parse(io.canonical(receipt)))
        except Exception: pass
        return digest
    client.MaintenanceTransport.__init__ = initialized
    client.Client.serve = served
    client.maintenance_cleanup_receipt = receipted
    try: return client.execute_maintenance(packet, source, **kwargs), observed, cleanup
    finally:
        client.MaintenanceTransport.__init__ = actual_init
        client.Client.serve = actual_serve
        client.maintenance_cleanup_receipt = actual_receipt


def bound_cleanup_observation(result, route, observed):
    # Reuse the real cleanup writer's successful independent readback. No
    # extra receipt read/write and no inferred remote process exit.
    unknown = {k: diagnostics.UNKNOWN for k in
        ('cleanup_receipt', 'ssh_exit', 'ssh_exit_observation', 'remote_final_record')}
    try:
        digest = result.get('client_cleanup_sha256')
        if type(digest) is not str or len(digest) != 64 or type(observed) is not dict: return unknown
        receipt = io.client_cleanup_record(observed.get('receipt'))
        if digest != observed.get('digest') or io.sha(io.canonical(receipt)) != digest: return unknown
        if receipt['route'] != route or receipt['original_binding'] != result['binding']: return unknown
        return {'cleanup_receipt': 'BOUND_READBACK',
            'ssh_exit': receipt['ssh_exit'] if receipt['ssh_exit'] is not None else diagnostics.UNKNOWN,
            'ssh_exit_observation': 'AFTER_CLIENT_CLEANUP',
            'remote_final_record': 'PRESENT_BOUND' if receipt['host_final_sha256'] is not None else 'ABSENT_BOUND'}
    except (OSError, ValueError, KeyError, io.Hold): return unknown


def worker(case,route):
    f.f.assert_guest_isolation()
    packet=io.parse((ROOT/'packet.json').read_bytes());data=io.parse((ROOT/'fixture-pins.json').read_bytes())
    pins=data['pins'];inputs=data['inputs'];legacy_sha=data['legacy_contexts_sha256']
    io.ASSETS['runtime_inputs']=io.sha(io.canonical(inputs))
    source=io.Source(packet['source'],packet['hashes']);f.bind_expected(source,pins,inputs,legacy_sha=legacy_sha)
    payload=(ROOT/'runtime.tar.gz').read_bytes() if route=='original' else None
    client.maintenance_bootstrap_original=client.maintenance_bootstrap
    client.maintenance_bootstrap=lambda raw:bootstrap(raw,pins,inputs,case,route,legacy_sha=legacy_sha)
    connections=[]
    def ssh(remote):connections.append(time.monotonic_ns());return f.ssh_argv(remote)
    client.ssh_argv=ssh
    kwargs=dict(password=f.PASSWORD,runtime_payload=payload,recover_once=route!='original')
    extra={}
    if case=='recovery_F1':
        result,observed,cleanup=execute_with_transport_observation(packet,source,**kwargs)
        extra={'transport_observation':observed,'cleanup_observation':bound_cleanup_observation(result,route,cleanup)}
    else:result=client.execute_maintenance(packet,source,**kwargs)
    f.f.write(ROOT/('client-'+route+'.json'),io.canonical({'result':result,'connections':len(connections),**extra}),0o600)
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
    if (case,route)==('recovery_F1','recovery-once'):
        trace['f1_client_transport']=diagnostics.transport_projection(
            value.get('transport_observation'),value.get('cleanup_observation'),trace)
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
    assert intents==acks==0,(intents,acks)
    actual_root=sum(p.stat().st_uid==0 for p in [f.f.WEB,*f.f.WEB.rglob('*')])
    assert actual_root==4,'ACTUAL_READ_ONLY_LIGHTING_OWNER_COUNT'
    assert not os.path.lexists(f.CUSTODY/'public-rights-20261014-1'/'owner-admission-intent')
    assert not os.path.lexists('/etc/tu1nz/public-web-bootstrap-r3/20261014-1/owner-admission-intent')
    assert trace['owner_finish'] is trace['owner_begin'] is None
    assert result['owner_evidence']=={'owner_intents':0,'owner_acks':0,'owner_entered':None if terminal else False,
        'client_owner_marker_absent':True}
    assert result['final_received'] is True and result['ssh_exit']==0
    # SSH waited/reaped by execute_maintenance; worker also reaped before end.
    cleanup_path=root/'client-cleanup.json' if route!='original' else root/'operator-records'/'client-cleanup.json'
    cleanup=io.client_cleanup_record(io.parse(cleanup_path.read_bytes()))
    assert io.sha(io.canonical(cleanup))==result['client_cleanup_sha256']
    assert cleanup['ssh_exit']==0 and cleanup['operational_handles_closed'] is True
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
        expected=io.R5_ORIGINAL_COMPLETE if case=='original' else io.R5_RECOVERY_COMPLETE
        assert result['status']==expected and final['primary'] is None
        assert trace['r5_finish_returned'] is True and trace['r5_finish_begin'] is not None
        assert count('r5_completion')==1 and final['r5_completion_sha256']
        assert final['owner_completion_sha256'] is None and final['publication_authorized'] is False
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
        'finish_cleanup_milliseconds':0 if terminal else ns(trace['r5_finish_begin'],end),
        'owner_entered':False,'final_received':result['final_received'],'process_ended':True,
        'largest_service_action_milliseconds':math.ceil(max(trace['service_ns'],default=0)/1_000_000),
        'terminal_prepare_milliseconds':ns(trace['terminal_begin'],trace['terminal_admitted']) if terminal else 0,
        'terminal_stop_milliseconds':ns(trace['terminal_admitted'],trace['terminal_stopped']) if terminal else 0,
        'terminal_cleanup_milliseconds':ns(trace['terminal_stopped'],end) if terminal else 0,
        'linked_records':len(rows),'flow_records':sum(r['kind'].startswith(('flow_','recovery_flow_')) for r in row_values),
        'largest_record_bytes':max(len(io.canonical(r)) for r in rows),'owner_intents':intents,'owner_acks':acks}
    assert owner==0 and prepare<=120000 and result_row['largest_service_action_milliseconds']<=20000
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
        source=io.Source(packet['source'],packet['hashes'])
        f.bind_expected(source,pins['pins'],pins['inputs'],legacy_sha=pins['legacy_contexts_sha256'])
        r=source.load('r3');denied=False
        try:
            custody=client.RecoveryCustody(r,packet['binding'],boot_id=packet['baseline']['boot_id'],
                source_sha256=io.sha(io.canonical(packet['hashes'])),deadline=time.monotonic()+10)
        except BaseException as error:
            denied=getattr(error,'primary',None)=='PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_RECOVERY_ORIGINAL_ROOT_NAMES_OR_PRIOR_ENTRY'
        else:custody.close()
        assert denied and snapshot(original_root)==before,'SECOND_RECOVERY_ENTRY_NOT_DENIED'
    row=measured(case,receipt,result,trace,began,end)
    extra={'f1_diagnostic':diagnostics.f1_diagnostic(trace)} if case=='recovery_F1' else {}
    return {'schema':'TU1NZ_REV4_NATIVE_CASE_V1','case':case,'phase':phase,'green':True,**extra,
        'production_source_files':production_hashes,'fixture_source_files':packet['hashes'],
        'fixture_artifact_sha256':io.sha(io.canonical(receipt)),
        'original_failed_hold_preserved':case!='original','second_recovery_denied_before_SSH':case!='original',
        'run':row,'host_acceptance':False}


def failure_fields(error):
    fields={'error_type':type(error).__name__,
        'code':getattr(error,'primary','NATIVE_FULL_ENTRY_ASSERTION'),
        'test_failure':diagnostics.capture(error)}
    counts=diagnostics.capture_owner_counts(error)
    if counts is not None:fields['owner_counts']=counts
    return fields


def failure_trace_fields(trace):
    # Only already retained diagnostics, after the failed worker has ended.
    fields={}
    point=diagnostics.validated_start_limit(trace.get('start_limit_failure'))
    if point is not None:fields['start_limit_failure']=point
    final=trace.get('final')
    fault=diagnostics.validated_host_fault(final.get('source_fault') if type(final) is dict else None)
    if fault is not None:fields['host_source_fault']=fault
    return fields


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
            if path.exists():
                result[route]=io.parse(path.read_bytes())
                trace=ROOT/('trace-'+route+'.json')
                trace_value=None
                if trace.exists():
                    trace_value=io.parse(trace.read_bytes())
                    result[route].update(failure_trace_fields(trace_value))
                if args.case=='recovery_F1':
                    result[route]['transport_failure']=diagnostics.transport_projection(
                        result[route].get('transport_observation'),result[route].get('cleanup_observation'),trace_value)
                    if route=='recovery-once':
                        result[route]['owner_profile']=diagnostics.owner_profile_projection(
                            trace_value.get('f1_owner_profile') if type(trace_value) is dict else None)
    finally:
        path=Path('/native-result.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:output.write(io.canonical(result));output.flush();os.fsync(output.fileno())
        subprocess.run(['/usr/bin/systemctl','--no-block','poweroff'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=True)
