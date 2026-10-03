"""Isolated concrete directional worker/adapter/cleanup validation stages."""
import os,sys,time,base64
from pathlib import Path
import anchor,manager,phase0,install,host,phase1,seal_boundary as sb,isolated_runtime as rt
from anchor import encode,digest,TERMINAL,Refused,Store,VALIDATION_ROOT
from publication import Journal
from typed_adapter import BoundManager
from worker import Worker
import root_validation as old,routing
from base_host import trusted_file

def execute(capsule,interpreter,interpreter_sha,transaction,case,scope):
 if os.geteuid()!=0 or case not in ('PRESEAL','POSTSEAL','UNKNOWN'):raise Refused('ISOLATED_CASE')
 old.CREATION_HOOK=scope.note;rt.CREATION_HOOK=scope.note
 m=manager.Manager('validation',lambda e:None,lambda:None);p=m.p
 old.exclusive_file(p['unitdir']+'/'+p['consumer'],b'[Service]\nType=oneshot\nExecStart=/usr/bin/true\n',0o644);m.action('daemon-reload')
 phase0.prepare(VALIDATION_ROOT,capsule['anchor'],[capsule['worker']],interpreter,interpreter_sha,list(host.VALIDATION_TARGETS),validation=True,created=lambda identity:scope.note(VALIDATION_ROOT,identity))
 s=Store(VALIDATION_ROOT,validation=True);j0=Journal(s.path/'phase0-journal',create=True);g=j1=None
 try:
  m=manager.Manager('validation',s.record,s.close_fence);files=install.file_backend('validation');bm=BoundManager(m,files,s)
  installation=install.Install(s,j0,files,bm,'validation');installation.run();installation.verify_start();installation.run()
  root=Path(rt.GUARD);root.mkdir(mode=0o700);st=root.stat();scope.note(root,(st.st_dev,st.st_ino));g=rt.GuardStore()
  contract=digest(b'ISOLATED_V11_AUTHORITY_CONTRACT_V1');boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  g.initialize({'transaction':transaction,'boot':boot,'contract_sha256':contract,'deadline_ns':time.monotonic_ns()+1200_000_000_000,'coordinator_pid':os.getpid(),'coordinator_start_ticks':1})
  f=host.ValidationFiles();originals=f.snapshot(f.targets,f.directories)
  if any(row!={'absent':True} for row in originals.values()):raise Refused('ISOLATED_NONEMPTY_PRESTATE')
  payload={host.VALIDATION_TARGETS[0]:b'raise SystemExit(0)\n',host.VALIDATION_TARGETS[1]:b'{"isolated":true}\n',host.VALIDATION_TARGETS[2]:('[Service]\nType=oneshot\nUser=root\nGroup=root\nPrivateNetwork=yes\nNoNewPrivileges=yes\nExecStart='+interpreter+' -I -B '+host.VALIDATION_TARGETS[0]+'\n').encode()}
  candidates={p:{'bytes':raw,'sha256':digest(raw),'mode':0o500 if p.endswith('.py') else 0o644,'uid':0,'gid':0} for p,raw in payload.items()}
  artifacts={'guard':digest(capsule['worker']),'authority':candidates[host.VALIDATION_TARGETS[1]]['sha256']}
  plan={'schema':1,'candidates':{p:{**r,'bytes':base64.b64encode(r['bytes']).decode()} for p,r in candidates.items()},'originals':originals,'artifact_manifest':artifacts}
  s.write('directional-plan.json',encode(plan));j1=Journal(s.path/'publication',create=True);j1.close();j1=None
  from bootstrap import plan_pin
  c={'schema':2,'transaction':transaction,'origin_boot':boot,'recovery_generation':0,'control_commit':sb.CONTROL,'control_tree':sb.TREE,'infra_basis':'b9fac72d94a0ddf7f1788131f9289f4a2844b6b7','guard_version':'v11-isolated-validation-3','guard_sha256':artifacts['guard'],'guard_contract_sha256':contract,'artifacts':artifacts,'artifact_manifest_sha256':digest(encode(artifacts)),'activation_manifest_sha256':plan_pin(s,candidates,originals),'base_sha256':digest(s.read('base.json')),'worker_pins':s.base()['workers']}
  sb.Chain(s).bind(c);g.close();g=None
  if case=='PRESEAL':
   b,g,j1=rt.factory(s)
   with b.locked():b.prepare_locked()
   j1.close();j1=None;g.close();g=None
   mode='directional-cleanup';expected=TERMINAL
  elif case=='UNKNOWN':
   g=rt.GuardStore();g.publish('SEALED',{'binding':{'transaction':'v11-'+'f'*32},'sealed':True});g.close();g=None
   mode='directional-cleanup';expected=sb.UNKNOWN
  else:mode='directional-activate';expected='COMPLETE'
  transport=Worker(s);selected=s.choose();result=transport.invoke_directional(selected,c,mode)
  if result!=expected:raise Refused('ISOLATED_DIRECTION_RESULT')
  routing.verify(s,m,result,trusted_file)
  # A new process re-opens all immutable data and objective state. This is
  # reboot ENTRY continuation, not a claim of an actual host reboot.
  again=transport.invoke_directional(selected,c,'directional-verify')
  if again!=expected:raise Refused('ISOLATED_FRESH_ENTRY')
  if transport.invoke_directional(selected,c,'directional-cleanup')!=expected:raise Refused('ISOLATED_CLEANUP_IDEMPOTENCE')
  routing.verify(s,m,result,trusted_file);transport.no_worker()
  return {'case':case,'state':result,'fresh_process_verified':True,'closed':s.closed(),'production_actions':False}
 finally:
  if g:g.close()
  if j1:j1.close()
  j0.close();s.close()

def launch(capsule,worker_b,interpreter,interpreter_sha,transaction,handoff,handoff_sha):
 import control_handoff,outer_supervisor,validation_scope
 verified=control_handoff.verify(handoff,handoff_sha) # No effects before pass.
 capsule={**capsule,'worker_pins':[digest(capsule['worker']),digest(worker_b)]}
 outer=Path('/var/lib')/('tu1nz-v11-isolated-validation-'+transaction[4:]);outer.mkdir(mode=0o700)
 stages=[]
 for num,case in enumerate(('LEGACY_ROOT_MATRIX','PRESEAL','POSTSEAL','UNKNOWN')):
  evidence=outer/('stage-%02d'%num);evidence.mkdir(mode=0o700);scope=validation_scope.Scope(evidence,capsule)
  tid='v11-'+digest(encode({'transaction':transaction,'stage':num}))[:32]
  def run():
   old.CREATION_HOOK=scope.note;rt.CREATION_HOOK=scope.note
   if case=='LEGACY_ROOT_MATRIX':
    rc=old.execute(capsule,worker_b,interpreter,interpreter_sha,tid)
    if rc:raise Refused('LEGACY_ROOT_MATRIX_FAILED')
    return {'case':case,'state':'PASSED'}
   return execute(capsule,interpreter,interpreter_sha,tid,case,scope)
  row=outer_supervisor.supervise(run,scope.restore)
  stages.append(row);old.exclusive_file(evidence/'stage-result.json',encode(row),0o600)
 result={'schema':3,'state':'ISOLATED_ROOT_VALIDATION_PASSED','handoff':verified,'stages':stages,'production_activation':False,'actual_host_reboot':False,'guardian_exact_prestate':True}
 old.exclusive_file(outer/'manifest.json',encode(result),0o600);print(encode(result).decode(),end='');return 0
