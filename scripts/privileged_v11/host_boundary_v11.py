"""Offline evidence classifier, not an activation or privilege-granting API."""
CLASSES = ('ISOLATED_CONTAINER_ROOT_RISK', 'HOST_ROOT_PATH_CONFIRMED',
           'CONTAINER_BOUNDARY_UNRESOLVED')

def classify(facts):
    """An enforcing LSM name/hash is not evidence of its individual decisions.

    The caller must supply reviewed boolean facts; unknown is never treated as
    false. No exploit, secret access, process execution or mutation occurs here.
    """
    required = ('inspection_complete', 'chatops_controls_source',
                'host_uid_zero', 'host_bind_writable', 'host_suid_enabled',
                'host_exec_enabled', 'host_caller_can_gain_privilege',
                'file_privilege_operations', 'lsm_allows_host_file_chain',
                'other_host_privilege_path', 'boundary_review_complete')
    if any(k not in facts or (facts[k] is not None and type(facts[k]) is not bool)
           for k in required):
        return {'class': CLASSES[2], 'reason': 'INCOMPLETE_OR_INVALID_EVIDENCE'}
    if facts['inspection_complete'] is not True:
        return {'class': CLASSES[2], 'reason': 'INSPECTION_INCOMPLETE'}
    chain = required[1:9]
    if all(facts[k] is True for k in chain):
        return {'class': CLASSES[1], 'reason': 'WRITABLE_BIND_PRIVILEGED_FILE_CHAIN'}
    if facts['other_host_privilege_path'] is True:
        return {'class': CLASSES[1], 'reason': 'SEPARATELY_PROVEN_HOST_PATH'}
    if all(facts[k] is True for k in chain[:-1]) and facts[chain[-1]] is None:
        return {'class': CLASSES[2], 'reason': 'LOADED_LSM_RULES_UNREADABLE'}
    if (facts['boundary_review_complete'] is True
            and facts['other_host_privilege_path'] is False
            and any(facts[k] is False for k in chain)):
        return {'class': CLASSES[0], 'reason': 'HOST_BOUNDARY_REVIEWED_NO_PROVEN_PATH'}
    return {'class': CLASSES[2], 'reason': 'BOUNDARY_REVIEW_INCOMPLETE'}
