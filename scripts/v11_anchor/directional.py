"""Fixed phase ownership and entrypoint shared by workers and phase-0 cleanup.

No external command, filename or unit name is accepted. Classification always
uses the objective boundary under the anchor + Guard locks, never elapsed time.
"""
from anchor import Refused,TERMINAL,digest,encode
import seal_boundary as sb
PRE='PRESEAL_WORKER'
POST='POSTSEAL_FORWARD_WORKER'
STOP='SECURED_STOP_WORKER'
MATRIX={
 'UNSEALED':(PRE,('ACTIVATE','RECOVER','VERIFY'),(TERMINAL,'COMPLETE',sb.UNKNOWN,sb.SEALED_STOP)),
 'SEALED':(POST,('RECOVER','VERIFY'),('COMPLETE',sb.SEALED_STOP,sb.UNKNOWN)),
 'UNKNOWN':(STOP,('RECOVER','VERIFY'),(sb.UNKNOWN,sb.SEALED_STOP)),
 'STOPPED':(STOP,('RECOVER','VERIFY'),(sb.UNKNOWN,sb.SEALED_STOP)),
}

class Driver:
 def __init__(self,boundary):self.b=boundary;self.s=boundary.s
 def validated(self):
  self.s.base();self.s.choose();self.s.journal();c=self.b.chain.context()
  self.b.h.verify_artifacts(c)
  return c
 def classification(self):
  self.validated()
  if self.s.exists('stop.json'):
   # A legacy retained stop is sticky; cannot be bypassed by the new chain.
   self.s.read('stop.json');return 'STOPPED'
  if self.b.prior_stop():return 'STOPPED'
  try:
   p=self.b.probe()
   if self.s.exists(sb.NAMES['SEAL_INTENT']):self.b.chain.intent()
   if self.s.exists(sb.NAMES['SEALED']):self.b.chain.sealed()
   if self.s.exists(sb.NAMES['POSTSEAL_COMPLETE']):self.b.chain.complete()
   if p['state']=='SEALED' and not self.s.exists(sb.NAMES['SEAL_INTENT']):return 'UNKNOWN'
   if p['state']=='UNSEALED' and (self.s.exists(sb.NAMES['SEALED']) or self.s.exists(sb.NAMES['POSTSEAL_COMPLETE'])):return 'UNKNOWN'
   return p['state']
  except Exception:return 'UNKNOWN'
 def job(self,role,action):
  c=self.validated()
  if role not in (PRE,POST,STOP) or action not in ('ACTIVATE','RECOVER','VERIFY'):raise Refused('WORKER_ACTION')
  return {'schema':1,'role':role,'action':action,'transaction':c['transaction'],'generation':c['recovery_generation'],'context_sha256':digest(encode(c)),'artifacts_sha256':c['artifact_manifest_sha256'],'base_sha256':c['base_sha256']}
 def result_verified(self,result):
  self.validated();self.b.close();self.b.h.confirm_closed()
  p=self.b.probe() if result not in (sb.UNKNOWN,sb.SEALED_STOP) else None
  if result==TERMINAL:
   if p['state']!='UNSEALED':raise Refused('WORKER_ROLLBACK_DIRECTION')
   self.b.h.verify_rollback()
  elif result=='COMPLETE':
   if p['state']!='SEALED':raise Refused('WORKER_FORWARD_DIRECTION')
   self.b.chain.complete();self.b.h.verify_final()
  elif result in (sb.UNKNOWN,sb.SEALED_STOP):
   if self.b.prior_stop()!=result:raise Refused('WORKER_STOP_RECEIPT')
   self.b.h.verify_inactive()
  else:raise Refused('WORKER_RESULT')
  return result
 def execute(self,job):
  if type(job)!=dict:raise Refused('WORKER_JOB_TYPE')
  with self.b.locked():
   expected=self.job(job.get('role'),job.get('action'))
   if job!=expected:raise Refused('WORKER_CONTEXT_REPLAY')
   state=self.classification();role,actions,ends=MATRIX[state]
   if job['role']!=role or job['action'] not in actions:raise Refused('WRONG_DIRECTIONAL_WORKER')
   self.s.record({'operation':role,'action':job['action'],'state':'INTENT','job_sha256':digest(encode(job))})
   if job['action']=='VERIFY':
    if state=='STOPPED':result=self.b.prior_stop() or self.b.stop(sb.UNKNOWN)
    elif state=='SEALED':result='COMPLETE'
    else:result=TERMINAL
   elif role==STOP:result=self.b.prior_stop() or self.b.stop(sb.UNKNOWN)
   elif job['action']=='ACTIVATE':result=self.b.run_locked()
   else:result=self.b.recover_locked()
   if result not in ends:raise Refused('WORKER_SUCCESSOR')
   self.result_verified(result)
   self.s.record({'operation':role,'action':job['action'],'state':'DONE','job_sha256':digest(encode(job)),'result':result})
   return result
 def selected_job(self,action):
  with self.b.locked():return self.job(MATRIX[self.classification()][0],action)
