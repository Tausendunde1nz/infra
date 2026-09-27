"""OFFLINE state-machine model. No OS adapter, no runnable live transaction."""
import copy

STEPS=('backup','watchdog','broker','sudoers_validate','sudoers_replace','polkit_replace',
       'remove_docker_group','restart_scoped_services','renew_sessions','independent_tests','finalize')
REQUIRED=('inventory_reviewed','includes_resolved','polkit_reviewed','replacements_tested',
          'services_without_docker_tested','rollback_verified','activation_authorized')


def plan(preconditions):
    missing=[k for k in REQUIRED if preconditions.get(k) is not True]
    if missing:raise ValueError('unmet_gates:'+','.join(missing))
    if preconditions.get('unknown_rules') or preconditions.get('unknown_processes'):
        raise ValueError('unresolved_scope')
    return STEPS


def simulate(original,preconditions,fail_at=None,rollback_fail=False):
    """Failure injection for design, not evidence that live restoration works."""
    steps=plan(preconditions);current=copy.deepcopy(original);backup=copy.deepcopy(original)
    completed=[];watchdog=False
    try:
        for step in steps:
            if step=='watchdog':watchdog=True
            if step==fail_at:raise RuntimeError('injected')
            if step=='broker':current['broker']='root-owned-fixed-ops'
            elif step=='sudoers_replace':current['sudoers']='exact-reviewed-candidate'
            elif step=='polkit_replace':current['polkit']='exact-reviewed-chatops-denial'
            elif step=='remove_docker_group':current['docker_member']=False
            elif step=='restart_scoped_services':current['service_groups']={k:tuple(g for g in v if g!=987) for k,v in current['service_groups'].items()}
            elif step=='renew_sessions':current['old_sessions_present']=False
            elif step=='finalize':watchdog=False
            completed.append(step)
    except RuntimeError:
        if rollback_fail:return {'status':'RECOVERY_REQUIRED','watchdog':True,'state':current,'completed':completed}
        # Configuration and service identities restored. Interactive process memory is not.
        current=backup
        return {'status':'ROLLED_BACK_MODEL','watchdog':False,'state':current,'completed':completed,
                'limitation':'No restoration of killed session memory or external side effects is modeled.'}
    return {'status':'MODEL_COMPLETE','watchdog':watchdog,'state':current,'completed':completed}
