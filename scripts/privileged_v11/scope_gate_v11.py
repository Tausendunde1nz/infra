"""Offline admission gate only. Does not install, migrate, execute or change a host."""
import hashlib
import json

def evaluate(observation):
    """Reject a currently evidenced chatops-writable executable under host UID 0.

    Host UID 0 inside a container is not equated with unrestricted host access.
    This gate enforces the requested executable-source boundary only.
    """
    required=('id','image','pid','uids','uid_map','process_path','python_script_args','mounts','paths')
    if any(k not in observation for k in required):
        return {'admission':'UNPROVEN','reason':'MISSING_CURRENT_EXECUTION_EVIDENCE'}
    if observation['process_path'] not in ('python','python3','/usr/bin/python3'):
        return {'admission':'UNPROVEN','reason':'UNREVIEWED_INTERPRETER'}
    if len(observation['python_script_args'])!=1:
        return {'admission':'UNPROVEN','reason':'AMBIGUOUS_SCRIPT'}
    script=observation['python_script_args'][0]
    if not isinstance(script,str) or not script.startswith('/') or '..' in script.split('/'):
        return {'admission':'UNPROVEN','reason':'UNSAFE_SCRIPT_PATH'}
    matches=[]
    for mount in observation['mounts']:
        destination=mount.get('Destination','').rstrip('/')
        if destination and (script==destination or script.startswith(destination+'/')):
            matches.append(mount)
    if len(matches)!=1 or matches[0].get('Type')!='bind':
        return {'admission':'UNPROVEN','reason':'MOUNT_MAPPING_NOT_UNIQUE'}
    mount=matches[0]
    source=mount['Source'].rstrip('/')+script[len(mount['Destination'].rstrip('/')):]
    rows={r.get('path'):r for r in observation['paths']}
    file=rows.get(source)
    parent=rows.get(source.rsplit('/',1)[0])
    if not file or not parent or not file.get('sha256') or file.get('type')!=32768 or parent.get('type')!=16384:
        return {'admission':'UNPROVEN','reason':'SOURCE_IDENTITY_INCOMPLETE'}
    if file.get('acl_xattrs') or parent.get('acl_xattrs'):
        return {'admission':'UNPROVEN','reason':'ACL_EFFECT_NOT_PROVEN'}
    if not isinstance(observation['uids'],list) or len(observation['uids'])!=4:
        return {'admission':'UNPROVEN','reason':'PROCESS_IDENTITY_INCOMPLETE'}
    writable=file.get('chatops_writable') is True or parent.get('chatops_writable') is True
    is_root=observation['uids']==['0','0','0','0']
    if is_root and writable:
        return {'admission':'BLOCKED','reason':'CHATOPS_WRITABLE_CODE_EXECUTED_AS_HOST_UID_ZERO','container':observation.get('container'),'source':source,'script':script,'source_sha256':file['sha256'],'container_root_is_not_unrestricted_host_root':True}
    if writable or is_root:
        return {'admission':'UNPROVEN','reason':'ADDITIONAL_EXECUTION_BOUNDARY_REVIEW_REQUIRED'}
    return {'admission':'NO_MATCH_FOR_THIS_BLOCKER','activation_authorized':False}

def binding(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
