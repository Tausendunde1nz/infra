"""Independent R5 integration at real local pipe/process/journal boundaries.

No SSH, sudo, Host or service operation. Only native observations/actions and
material admission are inert fixture inputs here. Authenticated Source and all
native observations remain separate tests/gates; these are not native timings.
"""
import base64
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as c
io=c.io
import tu1nz_public_bootstrap_r3 as r3

LOCAL_HOST = r'''
import os,sys,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
if not hasattr(os,'O_NOATIME'):os.O_NOATIME=0
import tu1nz_public_operator as c
io=c.io
import tu1nz_public_operator_host as host
import tu1nz_public_maintenance_r5_candidate as r5
r=r5.r3
mode=sys.argv[3]
assert sys.stdin.buffer.readline()==b'SYNTHETIC_LOCAL_ONLY\n'
w=io.Wire(0,1,deadline=time.monotonic()+30);w.bootstrap_started=time.monotonic()
w.send({'type':'ready','io_sha256':sys.argv[4]})
p=w.receive()
def init(self,source,baseline,plan,channel,binding,**kw):
 self.channel=channel;self.binding=binding;self.deadline=w.deadline
 self.owner=self.owner_result=None;self.owner_admission_started=False
 self.read_witness={'synthetic':True};self.r5_completion=None
 channel.host_fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
def observe(self,phase,*,deadline):
 if mode=='guard' and phase=='rights':raise io.Hold('PUBLIC_OPERATOR_SYNTHETIC_RIGHTS_DENIED')
 if phase=='r5_finish':
  functions={u:{'unit':u,'old':False,'fixture':True} for u in r.UNITS}
  for value in functions.values():self.channel.record('function_accepted',value)
  self.r5_completion={'schema':io.R5_COMPLETION_SCHEMA,'binding':self.binding,
   'backup_readback':{'fixture':True},'functions_sha256':io.sha(io.canonical(functions)),
   'probes_sha256':'c'*64,'lighting_read_witness_sha256':'d'*64,
   'owner_entered':False,'host_owner_marker_absent':True,'publication_authorized':False}
  self.channel.record('r5_completion',self.r5_completion)
 return r.Observation(r.TX,self.binding,phase,r5.R5MaintenanceFlow.required[phase],time.monotonic())
def perform(self,action,unit,*,deadline):
 value={'outcome':'CONFIRMED','action':action,'unit':unit}
 if action=='stop':value.update(cgroup_empty=True,no_job=True)
 return value
def close(self):
 return ['PUBLIC_BOOTSTRAP_SYNTHETIC_CLOSE_FAILED'] if mode=='cleanup' else []
r5.R5MaintenanceAdapter.__init__=init
r5.R5MaintenanceAdapter.observe=observe
r5.R5MaintenanceAdapter.perform=perform
r5.R5MaintenanceAdapter.close=close
r5.R5MaintenanceAdapter.fault=lambda self,e:r.FlowFailure(getattr(e,'primary',r.failure_code(e)))
host.maintenance_session_setup=lambda *a,**k:{'plan':b'SYNTHETIC','inputs':{},'coverage':{},'timing':{'after_ready_seconds':240}}
io.maintenance_packet_binding=lambda *a,**k:{}
s=SimpleNamespace(load=lambda n:{'r3':r,'r5_completion':r5,'replacement':r5.transition,'artifact':None}[n])
actual_send=w.send
def send(value):
 if value.get('type')=='final':
  if mode=='missing_final':return
  if mode=='deadline':w.deadline=time.monotonic()-1
 actual_send(value)
w.send=send
host.dispatch_maintenance(s,p,w)
'''


class IntegratedEntryTests(unittest.TestCase):
    def run_entry(self,mode='success'):
        temp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(temp.cleanup)
        root=Path(temp.name);root.chmod(0o700)
        remote=root/'inert-host-journal';remote.mkdir(mode=0o700)
        source=SimpleNamespace(bytes={'io':Path(io.__file__).read_bytes()},
            load=lambda n:r3 if n=='r3' else SimpleNamespace(validate=lambda *a,**k:None))
        packet={'route':'original','scope':{'schema':io.MAINTENANCE_SCOPE},'binding':'a'*64,
            'hashes':{'io':io.sha(source.bytes['io'])},'remaining_milliseconds':600000,
            'baseline':{'boot_id':'00000000-0000-0000-0000-000000000001',
                'http':{**{u:[] for u in r3.UNITS},'lighting':{'location':'host'}}}}
        bound={'documents':{'native_timing':{'transport_cleanup_reserve_milliseconds':10000}}}
        real_popen=subprocess.Popen;children=[]
        def spawn(argv,**kwargs):
            self.assertEqual(argv,c.ssh_argv(argv[-1]))
            child=real_popen([sys.executable,'-I','-B','-S','-c',LOCAL_HOST,
                str(Path(c.__file__).parent),str(remote),mode,packet['hashes']['io']],**kwargs)
            children.append(child);return child
        actual_send=io.Wire.send
        dropped=[False]
        def send(w,value):
            # A real wrong ACK, not a fabricated Host result or successful retry.
            if mode=='lost_ack' and value.get('type')=='persisted' and not dropped[0]:
                value={**value,'sha256':'0'*64};dropped[0]=True
            return actual_send(w,value)
        with patch.object(r3,'CUSTODY_PARENT',root/'custody'), \
             patch.object(io,'maintenance_packet_binding',return_value=bound), \
             patch.object(c.subprocess,'Popen',side_effect=spawn),patch.object(io.Wire,'send',send):
            result=c.execute_maintenance(packet,source,password=b'SYNTHETIC_LOCAL_ONLY',runtime_payload=b'')
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdin.closed and children[0].stdout.closed)
        records=root/'custody'/r3.TX/'operator-records'
        return result,records,remote

    def test_intended_mac_entry_host_dispatch_flow_final_readback_cleanup_and_reap(self):
        result,records,remote=self.run_entry()
        self.assertEqual(result['status'],io.R5_ORIGINAL_COMPLETE)
        self.assertEqual(result['owner_evidence'],{'owner_intents':0,'owner_acks':0,
            'owner_entered':False,'client_owner_marker_absent':True})
        self.assertTrue(result['final_received']);self.assertEqual(result['ssh_exit'],0)
        self.assertEqual(result['client_cleanup'],[]);self.assertEqual(result['host_cleanup'],[])
        final=io.parse((records/'final.json').read_bytes())
        proof=c.maintenance_closed_chain(records,'a'*64,final,deadline=time.monotonic()+5)
        self.assertEqual(proof['count'],len(list(remote.glob('*.json'))))
        self.assertEqual(result['client_cleanup_sha256'],io.sha((records/'client-cleanup.json').read_bytes()))
        for record in remote.glob('*.json'):self.assertEqual(record.read_bytes(),(records/record.name).read_bytes())
        self.assertFalse(result['r2_dispatch'])

    def test_guard_lost_ack_missing_final_deadline_and_cleanup_all_remain_hold(self):
        for mode in ('guard','lost_ack','missing_final','deadline','cleanup'):
            with self.subTest(mode=mode):
                result,records,remote=self.run_entry(mode)
                self.assertEqual(result['status'],'HOLD')
                self.assertTrue(result['client_cleanup_sha256'])
                if mode in ('missing_final','deadline'):self.assertFalse(result['final_received'])
                if mode=='cleanup':self.assertIn('PUBLIC_BOOTSTRAP_SYNTHETIC_CLOSE_FAILED',result['host_cleanup'])
                rows=[io.parse(p.read_bytes()) for p in records.glob('[0-9]*.json')]
                self.assertEqual(sum(r['kind']=='owner_object_intent' for r in rows),0)
                self.assertEqual(sum(r['kind']=='owner_object_ack' for r in rows),0)
                self.assertFalse((records.parent/'owner-admission-intent').exists())
                receipt=io.client_cleanup_record(io.parse((records/'client-cleanup.json').read_bytes()))
                self.assertEqual(receipt['status'],'HOLD');self.assertFalse(receipt['completion_claimed'])

    def test_old_scope_and_missing_completion_source_are_rejected(self):
        self.assertNotEqual(io.MAINTENANCE_SCOPE,'TU1NZ_MAIN_SERVER_REV4_APPROVED_SCOPE_V1')
        data={k:b'# inert' for k in set(io.MODULES)|set(io.ASSETS)}
        del data['r5_completion']
        with self.assertRaisesRegex(io.Hold,'SOURCE_MEMBERS'):
            io.Source({k:base64.b64encode(v).decode() for k,v in data.items()},{k:io.sha(v) for k,v in data.items()})
        self.assertEqual(set(c.INFRA_FILES)|set(c.CONTROL_FILES),set(io.MODULES)|set(io.ASSETS))
        contract=Path(c.__file__).parent.parent/'docs/MAIN_SERVER_R5_COMPLETION_CONTRACT_V1.txt'
        self.assertEqual(io.sha(contract.read_bytes()),io.MAINTENANCE_DECISION_SHA)

    def test_production_approval_pin_binds_actual_conditional_document(self):
        document=Path(c.__file__).parent.parent/'docs/MAIN_SERVER_R5_CONDITIONAL_APPROVAL_20261120.json'
        raw=document.read_bytes();approval=io.parse(raw)
        self.assertEqual(io.sha(raw),io.MAINTENANCE_APPROVAL_SHA)
        self.assertEqual(approval['schema'],'TU1NZ_MAIN_SERVER_R5_CONDITIONAL_APPROVAL_V1')
        self.assertEqual(approval['authority'],'Daniel')
        self.assertFalse(approval['separate_production_go_present'])
        self.assertEqual(approval['host']['id'],109772243)
        self.assertEqual(approval['host']['machine_sha256'],io.MAINTENANCE_MACHINE)
        self.assertEqual(approval['contract_sha256'],io.MAINTENANCE_DECISION_SHA)
        self.assertEqual(approval['owner_plan_sha256'],io.MAINTENANCE_OWNER_PLAN)
        self.assertFalse(approval['maintenance_scope']['owner_entry'])
        self.assertEqual(approval['maintenance_scope']['services'],list(r3.UNITS))
        # Later Source/release/material/review hashes must not be embedded in
        # the prerequisite approval: that would make its compiled pin cyclic.
        self.assertFalse({'source_sha256','release_sha256','baseline_sha256',
            'current_observation_sha256','scope_sha256','review_sha256'} & set(approval))
        self.assertNotEqual(io.sha(raw+b'\n'),io.MAINTENANCE_APPROVAL_SHA)

    def test_all_eight_materials_and_completion_source_are_individually_bound(self):
        from tests.test_public_maintenance import MaintenanceMaterialBoundaryTests
        helper=MaintenanceMaterialBoundaryTests();self.addCleanup(helper.doCleanups)
        values=helper.fixture();scope,baseline,material,source,*_=values
        helper.check(values)
        for name in material:
            changed={**material,name:material[name]+b'\n'}
            with self.subTest(material=name),self.assertRaises(io.Hold):
                io.maintenance_material_binding(scope,baseline,changed,source_hashes=source,
                    review_sha256=io.sha(material['review']))
        with self.assertRaises(io.Hold):
            io.maintenance_material_binding(scope,baseline,material,source_hashes={**source,'r5_completion':'b'*64},
                review_sha256=io.sha(material['review']))

    def test_native_matrix_requires_separate_measured_calibration_and_verification(self):
        from tests.test_public_maintenance_transport import synthetic_timing
        from tests.test_public_maintenance_ci import NativeBoundaryTests
        import tu1nz_public_maintenance_ci as ci
        hashes,artifact,records=NativeBoundaryTests().fixture()
        self.assertEqual(len(records),6)
        for case in records:
            for key,value in (('owner_intents',1),('owner_acks',1),('owner_entered',True),
                              ('final_received',False),('process_ended',False),('finish_cleanup_milliseconds',-1)):
                changed=copy.deepcopy(case);changed['run'][key]=value
                with self.subTest(case=case['case'],key=key),self.assertRaises(ci.ci.CIError):
                    ci.validate_case(changed,case['case'],'calibration',hashes)
        proof=synthetic_timing(hashes,artifact)
        proof['schema']='TU1NZ_REV4_FULL_NATIVE_TIMING_V1'
        with self.assertRaises(io.Hold):io.maintenance_timing_binding(proof,source_hashes=hashes,artifact=artifact)


class RecoveryCompletionReadbackTests(unittest.TestCase):
    def closed(self, *, owner=False, bad_seed=False, missing_final=False):
        temp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(temp.cleanup)
        root=Path(temp.name);root.chmod(0o700)
        seed={k:'a'*64 for k in ('original_binding','ready_sha256','source_sha256','artifact_sha256',
            'mac_tail_sha256','host_tail_sha256','original_failure_sha256','fresh_state_sha256')}
        seed.update(schema='TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE',transaction=r3.TX,machine=r3.MACHINE,
            boot_id='00000000-0000-0000-0000-000000000001',owner_plan_sha256=r3.OWNER_PLAN,
            original_status='FAILED_HOLD',unconfirmed_mac_tail=None)
        binding=io.recovery_binding(seed);functions={u:{'unit':u,'old':False} for u in r3.UNITS}
        witness={'schema':io.R5_COMPLETION_SCHEMA,'binding':binding,'functions_sha256':io.sha(io.canonical(functions)),
            'host_owner_marker_absent':True,'owner_entered':False,'publication_authorized':False}
        cleanup={'status':io.R5_RECOVERY_COMPLETE,'primary':None,'abort':[],'cleanup':[],
            'owner_completion_sha256':None,'r5_completion_sha256':io.sha(io.canonical(witness)),
            'publication_authorized':False,'original_status':'FAILED_HOLD','original_evidence':dict(seed),
            'client_cleanup_still_required':True,'r2_dispatch':False}
        if bad_seed:cleanup['original_evidence']['original_failure_sha256']='b'*64
        values=[('recovery_context',seed),*[( 'function_accepted',v) for v in functions.values()],
            ('r5_completion',witness)]
        if owner:values.append(('owner_object_intent',{}))
        values.append(('operator_cleanup',cleanup));previous=binding
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            for index,(kind,value) in enumerate(values,1):
                row={'sequence':index,'binding':binding,'previous':previous,'kind':kind,'value':value}
                raw=io.canonical(row);io.exclusive(fd,f'{index:03}-{kind}.json',raw);previous=io.sha(raw)
            final={'type':'final',**cleanup,'source_fault':None,'slot_consumed':False}
            if not missing_final:io.exclusive(fd,'final.json',io.canonical(final))
        finally:os.close(fd)
        return root,binding,final

    def test_recovery_final_and_original_hold_are_bound_to_closed_chain(self):
        root,binding,final=self.closed()
        proof=c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)
        self.assertEqual(proof['owner_evidence'],{'owner_intents':0,'owner_acks':0,'owner_entered':False})
        self.assertEqual(final['original_status'],'FAILED_HOLD')
        for fault in ('owner','bad_seed','missing_final'):
            with self.subTest(fault=fault):
                root,binding,final=self.closed(**{fault:True})
                with self.assertRaises(io.Hold):c.maintenance_closed_chain(root,binding,final,deadline=time.monotonic()+10)

    def test_missing_unknown_or_true_native_completion_fields_never_pass(self):
        from tests.test_public_maintenance_ci import NativeBoundaryTests
        import tu1nz_public_maintenance_ci as ci
        hashes,_,records=NativeBoundaryTests().fixture()
        for key in ('owner_entered','final_received','process_ended','finish_cleanup_milliseconds'):
            for value in (None,'UNKNOWN',1):
                row=copy.deepcopy(records[1]);row['run'][key]=value
                # One millisecond is a valid measured interval, not a boolean proof.
                if key=='finish_cleanup_milliseconds' and value==1:continue
                with self.subTest(key=key,value=value),self.assertRaises(ci.ci.CIError):
                    ci.validate_case(row,'recovery_F1','calibration',hashes)

if __name__=='__main__':unittest.main()
