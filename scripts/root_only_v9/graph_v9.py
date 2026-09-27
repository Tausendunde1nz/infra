"""Proof obligations for the affected authority edges; no boolean waiver flags.

An old literal inventory is not transformed into semantic closure. Unresolved
reachable edges are rejected. Changes may use only approved fixed dispositions.
"""
from policy_v9 import Refused,authority_gate
KINDS={'EXEC','IMPORT','CONFIG','PRIVILEGED_WRITE','TRIGGER','DOCKER_API','SUDO'}

def verify_graph(graph,evidence):
 if set(graph)!={'scope','roots','nodes','edges'} or graph['scope']!='chatops-root-authority-v9':raise Refused('graph schema/scope')
 nodes=graph['nodes'];edges=graph['edges'];roots=graph['roots']
 if not nodes or not roots or len(roots)!=len(set(roots)):raise Refused('graph coverage')
 for node_id,node in nodes.items():
  if set(node)!={'disposition','proof'}:raise Refused('node schema')
  if node['disposition'] not in ('TRUSTED_FIXED','REVOKED','QUARANTINED','INDEPENDENT_CONTRACT'):raise Refused('unresolved node')
  if node['proof'] not in evidence or evidence[node['proof']].get('verified') is not True:raise Refused('missing actual node proof')
 seen=set();pending=list(roots)
 while pending:
  node=pending.pop()
  if node in seen:continue
  if node not in nodes:raise Refused('unresolved root')
  seen.add(node)
  for edge in edges:
   if set(edge)!={'source','target','kind','resolution'} or edge['kind'] not in KINDS or edge['resolution']!='FIXED':raise Refused('unresolved semantic edge')
   if edge['source']==node:
    if edge['target'] not in nodes:raise Refused('missing edge target')
    if nodes[node]['disposition'] not in ('REVOKED','QUARANTINED'):pending.append(edge['target'])
 if seen!=set(nodes):raise Refused('unreviewed/unreachable graph entries')
 return {'verified':True,'nodes':len(seen),'edges':len(edges),'scope':graph['scope']}


def closure(evidence,graph):
 # Kernel assertions are always required independently of the graph model.
 authority_gate(evidence['docker_authority'])
 return verify_graph(graph,evidence['nodes'])
