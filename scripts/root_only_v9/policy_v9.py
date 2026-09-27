"""Authority, persistence and rollback policy for the fixed TU1NZ migration."""
from dataclasses import dataclass

SOCKET='/run/docker.sock'
DOCKER_GID=987
CHATOPS_UID=1001
DROPIN='[Socket]\nSocketUser=root\nSocketGroup=root\nSocketMode=0600\n'
PHASES=('backup','watchdog','install_components','validate_units_sudoers','socket_persistence',
 'clients_before','socket_cutover','root_docker','fresh_chatops_denied','old_contexts_denied',
 'monitoring_containers','remove_membership','remove_unsafe_sudo','quarantines',
 'broker_tests','application_checks','authority_graph','finalize')
SEAL_PHASE='remove_membership'
class Refused(RuntimeError):pass


def persistence(facts):
 if facts.get('socket_path')!=SOCKET:raise Refused('unexpected socket')
 if facts.get('socket_creator')=='systemd':
  if facts.get('dockerd_hosts')!=['fd://'] or facts.get('socket_unit')!='docker.socket':raise Refused('contradictory creator')
  if facts.get('daemon_hosts') or facts.get('daemon_group'):raise Refused('conflicting daemon settings')
  if facts.get('other_listeners'):raise Refused('additional daemon listener')
  return {'kind':'SYSTEMD_DROPIN','content':DROPIN,'restart_required':False}
 if facts.get('socket_creator')=='dockerd':
  # This alternate model is never silently applied to the observed fd:// host.
  if facts.get('socket_unit_active') or facts.get('dockerd_hosts')!=['unix://'+SOCKET]:raise Refused('conflicting creator')
  return {'kind':'DOCKERD_REQUIRES_SEPARATE_VALIDATED_INSTALLER','activation_ready':False}
 raise Refused('creator unknown')


def effective_socket(base,dropins):
 values={};seen=[]
 for name,text in [('vendor',base)]+sorted(dropins.items()):
  section=None
  for line in text.splitlines():
   line=line.strip()
   if not line or line.startswith(('#',';')):continue
   if line.startswith('['):section=line;continue
   if section!='[Socket]' or '=' not in line:continue
   k,v=line.split('=',1)
   if k in ('SocketUser','SocketGroup','SocketMode'):values[k]=v;seen.append((name,k,v))
 return values,seen


def validate_persistence(base,dropins):
 values,_=effective_socket(base,dropins)
 if values!={'SocketUser':'root','SocketGroup':'root','SocketMode':'0600'}:raise Refused('effective socket settings')
 return True


def identity(row):return tuple(row[k] for k in ('pid','start_ticks','uid','gid','cgroup','namespace'))

def client_gate(clients,before,after,accepted):
 if before!=after:raise Refused('socket inode reused/replaced')
 for row in clients:
  if row.get('fd_snapshot_complete') is not True or row.get('peer_resolved') is not True:raise Refused('unknown connected client')
  if row.get('identity_before')!=row.get('identity_after'):raise Refused('pid identity changed')
  if row.get('chatops_controlled') is not False:
   if row.get('transient_cli') is True:return 'WAIT_AND_RESCAN'
   raise Refused('chatops connected authority')
  if identity(row) not in accepted:raise Refused('unaccepted connected client')
 return 'CLEAR'


def dac_connect_allowed(uid,gids,owner,group,mode,caps=()):
 # Linux pathname AF_UNIX connect requires write access; parent search is a
 # separate preflight gate. Model never claims to replace a real kernel probe.
 if uid==0 or 'CAP_DAC_OVERRIDE' in caps:return True
 if uid==owner:return bool(mode&0o200)
 if group in gids:return bool(mode&0o020)
 return bool(mode&0o002)


def authority_gate(facts):
 if facts.get('socket')!={'uid':0,'gid':0,'mode':0o600}:raise Refused('socket not root only')
 for key in ('socket_identity_stable','all_namespaces_reviewed','fd_audit_complete',
             'other_gid_interfaces_closed','fresh_connection_denied','old_context_connections_denied',
             'broker_no_passthrough','root_docker_ok','monitoring_ok'):
  if facts.get(key) is not True:raise Refused(key)
 if facts.get('chatops_open_peers')!=[]:raise Refused('retained open authority')
 if facts.get('chatops_is_docker_member') is not False:raise Refused('membership retained')
 # Numeric stale groups do not veto a proven authority boundary.
 return True


def rollback_policy(sealed,completed):
 if sealed:return {'socket':'KEEP_ROOT_ONLY','membership':'KEEP_REVOKED','unsafe_sudo':'KEEP_REMOVED','unsafe_triggers':'KEEP_QUARANTINED'}
 return {'socket':'RESTORE_EXACT_METADATA','membership':'UNCHANGED','unsafe_sudo':'UNCHANGED','unsafe_triggers':'UNCHANGED'}


def restart_permissions(authority_closed):
 if not authority_closed:raise Refused('authority not closed')
 return {'tu1nz_agentmode.service':False,'tu1nz-adult-public-s8-telegram.service':False,'mychatbuddy-private-alpha.service':False}
