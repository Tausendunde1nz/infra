"""Retained cleanup; no decommission and no backward operation after seal."""
from anchor import Refused,TERMINAL,digest,encode
from directional import Driver,MATRIX,STOP
import seal_boundary as sb

class Cleanup:
 def __init__(self,boundary):self.b=boundary;self.driver=Driver(boundary)
 def run(self):
  with self.b.locked():
   c=self.driver.validated();before=self.b.s.base();selected=self.b.s.choose()
   state=self.driver.classification()
   self.b.s.record({'operation':'PHASE0_CLEANUP','state':'INTENT','direction':state,'context_sha256':digest(encode(c))})
   if state in ('UNKNOWN','STOPPED'):
    # No cleanup_staged call; even deleting a tempfile requires direction.
    result=self.b.prior_stop() or self.b.stop(sb.UNKNOWN)
   else:
    result=self.b.recover_locked()
    if result in (TERMINAL,'COMPLETE'):
     # Host enumerates only Files' inode-bound staging receipts, not globs.
     self.b.h.cleanup_owned_temporaries()
   if self.b.s.base()!=before or self.b.s.choose()!=selected:raise Refused('CLEANUP_RECOVERY_BASE_DRIFT')
   self.driver.result_verified(result)
   self.b.s.record({'operation':'PHASE0_CLEANUP','state':'DONE','direction':state,'result':result})
   return result
