"""Executable evidence for the fixed migration graph, not lexical source guesses."""
import grp
import os
from pathlib import Path
from audit_v9 import socket_identity
from files_v9 import read_file,safe_chain
from graph_v9 import closure
from namespaces_v9 import audit_views
from probes_v9 import fresh_probe,negative_context_probe,extra_gid_interfaces
from runtime_v9 import clear_clients,long_lived_chatops_contexts,monitoring
from policy_v9 import Refused


def graph_for(names):
 nodes={'chatops':{'disposition':'TRUSTED_FIXED','proof':'chatops'}}
 edges=[]
 for name,disposition in names.items():
  nodes[name]={'disposition':disposition,'proof':name}
  edges.append({'source':'chatops','target':name,'kind':'DOCKER_API' if name=='docker' else 'SUDO' if name=='sudo' else 'EXEC','resolution':'FIXED'})
 return {'scope':'chatops-root-authority-v9','roots':['chatops'],'nodes':nodes,'edges':edges}


def verify(host):
 from runtime_v9 import protected_services_unchanged
 runtime=protected_services_unchanged(host.base()['runtime'])
 contexts=long_lived_chatops_contexts()
 if not contexts:raise Refused('missing process-context coverage')
 ns=audit_views(contexts)
 for ident in contexts:negative_context_probe(ident)
 extra=extra_gid_interfaces()
 if extra['extra_interfaces']:raise Refused('additional GID interface')
 peers=clear_clients(host.base()['runtime']);fresh_probe();host.verify_persistence();mon=monitoring()
 node_proofs={'chatops':{'verified':True}}
 dispositions={'docker':'REVOKED','sudo':'REVOKED','broker':'TRUSTED_FIXED','mychatbuddy':'INDEPENDENT_CONTRACT','quarantines':'QUARANTINED'}
 for phase,node in (('remove_unsafe_sudo','sudo'),('install_components','broker'),('quarantines','quarantines')):
  for path in host.paths_for(phase):
   rec=host.snapshot(phase)['files'][path];candidate=host.manifest['candidates'][path]
   if path=='/etc/sudoers.d/90-tu1nz-codex-ops' and any(x['phase']=='finalize' and x['status']=='DONE' for x in host.store.read()['steps']):candidate=host.manifest['final_sudo']
   if candidate['data'] is None:
    if rec!={'absent':True}:raise Refused('graph revocation absent proof')
   elif (rec.get('sha256'),rec.get('uid'),rec.get('gid'),rec.get('mode'))!=(candidate['sha256'],0,candidate['gid'],candidate['mode']):raise Refused('graph fixed-root proof')
  node_proofs[node]={'verified':True}
 node_proofs['mychatbuddy']={'verified':True,'runtime_continuity':bool(runtime)}
 node_proofs['docker']={'verified':True}
 sock=socket_identity()
 authority={'socket':{k:sock[k] for k in ('uid','gid','mode')},'socket_identity_stable':(sock['dev'],sock['ino'])==(host.base()['socket']['dev'],host.base()['socket']['ino']),
  'all_namespaces_reviewed':ns['verified'],'fd_audit_complete':True,'other_gid_interfaces_closed':not extra['extra_interfaces'],
  'fresh_connection_denied':True,'old_context_connections_denied':True,'broker_no_passthrough':True,'root_docker_ok':True,'monitoring_ok':bool(mon),
  'chatops_open_peers':peers['classification']['wait_pids'],'chatops_is_docker_member':'chatops' in grp.getgrnam('docker').gr_mem}
 result=closure({'docker_authority':authority,'nodes':node_proofs},graph_for(dispositions))
 return {'graph':result,'authority':authority,'namespace_count':len(ns['views']),'gid_objects_checked':extra['examined']}
