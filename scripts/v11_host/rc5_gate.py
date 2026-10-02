"""Aggregate-only RC5 gate. No start authority, requests, or retained endpoints.
The producer must be the pinned PR68 observer. Never equate a snapshot with
absence of egress throughout a window. The outer V11 runner never starts RC5.
"""
import hashlib,ipaddress,re
from datetime import datetime,timezone
SOURCE_SHA='c9e47a406892db70b9f3543181ca4eee2221067145eb3105cb335a77d273917b'
class Refused(ValueError):pass

def activity(counts):
 if type(counts) is not dict or set(counts)!={'owner_bindings','provider_reservations','provider_leases','delivered_updates'} or any(type(v) is not int or v!=0 for v in counts.values()):raise Refused('HOLD_ACTIVITY')

def heartbeat(before,after,start,end):
 if type(after) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}',after):raise Refused('HEARTBEAT_SHAPE')
 try:
  value=datetime.strptime(after,'%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
  lo=datetime.fromisoformat(start);hi=datetime.fromisoformat(end)
  if lo.tzinfo is None or hi.tzinfo is None or not lo<=value<=hi:raise Refused('HEARTBEAT_WINDOW')
 except (ValueError,TypeError):raise Refused('HEARTBEAT_WINDOW') from None
 if before==after:raise Refused('HEARTBEAT_UNCHANGED')
 return hashlib.sha256(after.encode()).hexdigest()

def sockets(dns,connections,dns_rc=0,socket_rc=0):
 if dns_rc!=0 or socket_rc!=0 or not dns or type(dns) not in (list,tuple) or type(connections) not in (list,tuple):raise Refused('PROBE_FAILURE')
 try:
  allowed={str(ipaddress.IPv4Address(a)) for a in dns}
  if any(a!=str(ipaddress.IPv4Address(a)) for a in dns):raise ValueError()
  if len(connections)>1:raise ValueError()
  for row in connections:
   if type(row) not in (list,tuple) or len(row)!=2 or type(row[1]) is not int or row[1]!=443 or str(ipaddress.IPv4Address(row[0])) not in allowed:raise ValueError()
 except (TypeError,ValueError,ipaddress.AddressValueError):raise Refused('SOCKET_CLASSIFICATION') from None
 return {'class':'telegram_long_poll_snapshot','established':len(connections),'proves_no_egress':False}

def attest(source_sha,before_counts,after_counts,before_heartbeat,after_heartbeat,start,end,dns,connections,dns_rc=0,socket_rc=0):
 if source_sha!=SOURCE_SHA:raise Refused('SOURCE_PIN')
 activity(before_counts);activity(after_counts)
 marker=heartbeat(before_heartbeat,after_heartbeat,start,end)
 result=sockets(dns,connections,dns_rc,socket_rc)
 return {'status':'PASSED','hold_counts_zero':True,'heartbeat_marker':marker,'transport':result,'start_authorized':False}

def outer_policy(policy):
 if policy!='PR68_CLASSIFIED_POINT_IN_TIME':raise Refused('LEGACY_OR_UNKNOWN_EGRESS_GATE')
 return True
