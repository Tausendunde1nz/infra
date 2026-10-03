"""Pure arming/recovery decision. A valid coordinator lease prevents rollback.
Only a verified inner Store.current() may supply state to the production adapter.
"""
from core import binding_valid,boot_valid,Refused

def route(outer,current,boot,now_ns,alive):
 if not binding_valid(outer) or not boot_valid(boot) or type(now_ns)!=int or now_ns<0 or type(alive)!=bool:raise Refused('RECOVERY_INPUT')
 b=current['binding']
 if {'transaction':b['transaction'],'origin_boot':b['boot'],'contract_sha256':b['contract_sha256']}!=outer:raise Refused('RECOVERY_BINDING')
 if type(b['deadline_ns'])!=int or b['deadline_ns']<0 or type(current['sealed'])!=bool:raise Refused('RECOVERY_STATE')
 if current['phase']=='ROLLED_BACK_PRESEAL':
  if current['sealed']:raise Refused('SEALED_ROLLBACK_CONTRADICTION')
  return 'VERIFY_PRESEAL_TERMINAL'
 if current['phase']=='COMPLETED':
  if not current['sealed']:raise Refused('UNSEALED_COMPLETION')
  return 'VERIFY_FORWARD_TERMINAL'
 if boot==b['boot'] and now_ns<b['deadline_ns'] and alive:return 'WAIT'
 return 'SECURED_STOP' if current['sealed'] else 'RECOVER_PRESEAL'
