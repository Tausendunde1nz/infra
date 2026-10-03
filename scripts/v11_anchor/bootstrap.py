"""Attestation-gated Bootstrap. Importing never starts a transaction.
No caller-provided command is executed. The bound publication plan is data only.
"""
from anchor import *
from attestation import Gate
import phase0

def plan_pin(store,candidates,originals):
 if set(candidates)!=set(store.base()['phase1_paths']) or set(originals)!=set(candidates):raise Refused('BOOTSTRAP_SCOPE')
 pins={}
 for p,row in candidates.items():
  if set(row)!={'bytes','sha256','mode','uid','gid'} or type(row['bytes'])!=bytes or digest(row['bytes'])!=row['sha256'] or row['uid']!=0 or row['gid']!=0 or row['mode'] not in (0o400,0o500,0o644):raise Refused('BOOTSTRAP_CANDIDATE')
  pins[p]={'sha256':row['sha256'],'uid':row['uid'],'gid':row['gid'],'mode':row['mode']}
 return digest(encode({'schema':1,'base_sha256':digest(store.read('base.json')),'candidates':pins,'originals':originals}))
class Bootstrap:
 def __init__(self,store,installer,host):self.s=store;self.i=installer;self.h=host;self.gate=Gate(store)
 def stage(self,context,boot,recovery_generation,candidates,originals):
  try:
   phase0.phase1_admitted(self.s,self.h)
   expected=plan_pin(self.s,candidates,originals)
   if context['activation_manifest_sha256']!=expected:raise Refused('BOOTSTRAP_ACTIVATION_PIN')
   with self.s.locked():
    if self.s.exists('phase1.json') or self.s.exists('bootstrap.json'):raise Refused('BOOTSTRAP_DUPLICATE')
    receipt=self.gate.admit_locked(context,boot,recovery_generation,expected)
    self.s.write('bootstrap.json',encode({'schema':1,'state':'ATTESTED_BOOTSTRAP','context_sha256':digest(encode(context)),'transaction':context['transaction'],'phase_manifest_sha256':expected,'admission':receipt}))
   result=self.i.start(context['transaction'],candidates,originals)
   if result not in ('PHASE1_PUBLISHED_FENCED',TERMINAL):raise Refused('BOOTSTRAP_NONTERMINAL')
   return result
  except Exception:
   self.s.stop('BOOTSTRAP_ADMISSION_OR_PUBLICATION_FAILED');self.h.confirm_closed();raise
 def verify_resume(self,context,boot,recovery_generation,candidates,originals):
  with self.s.locked():
   expected=plan_pin(self.s,candidates,originals)
   row=parse(self.s.read('bootstrap.json'))
   receipt=self.gate.admit_locked(context,boot,recovery_generation,expected,resume=True)
   if row!={'schema':1,'state':'ATTESTED_BOOTSTRAP','context_sha256':digest(encode(context)),'transaction':context['transaction'],'phase_manifest_sha256':expected,'admission':receipt}:raise Refused('BOOTSTRAP_RESUME_BINDING')
   return receipt
