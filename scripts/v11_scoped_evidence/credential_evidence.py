"""Resolve systemctl's unprintable credential arrays only with typed D-Bus proof.
No root collection, no permissive fallback, no raw values in returned evidence.
"""
import hashlib,json,re
PROPERTIES=('LoadCredential','LoadCredentialEncrypted')
class Refused(RuntimeError):pass

def evaluate(property_name,rendered,bus_json):
 if property_name not in PROPERTIES:raise Refused('PROPERTY_SCOPE')
 if rendered!=property_name+'=[unprintable]':raise Refused('NOT_EXACT_UNPRINTABLE_RENDERING')
 if type(bus_json) is not bytes or len(bus_json)>262144:raise Refused('RESPONSE_SIZE')
 try:obj=json.loads(bus_json)
 except (ValueError,UnicodeError):raise Refused('RESPONSE_JSON') from None
 if type(obj) is not dict or set(obj)!={'type','data'} or obj['type']!='a(ss)' or type(obj['data']) is not list:raise Refused('DBUS_SIGNATURE')
 for row in obj['data']:
  if type(row) is not list or len(row)!=2 or any(type(v) is not str for v in row):raise Refused('DBUS_ROW')
 return {'property':property_name,'signature':'a(ss)','entries':len(obj['data']),
  'empty_proven':obj['data']==[],'status':'EMPTY_PROVEN' if not obj['data'] else 'UNRESOLVED_NONEMPTY',
  'response_sha256':hashlib.sha256(bus_json).hexdigest()}

def resolve_unit(unit,proofs):
 if type(proofs) is not list or len(proofs)!=2 or {x.get('property') for x in proofs}!=set(PROPERTIES):raise Refused('PROOF_SET')
 if not re.fullmatch(r'(trendwatch2-(morning|midday|afternoon|evening)|trendwatch-fetch|tu1nz_agentmode)\.service',unit):raise Refused('UNIT_SCOPE')
 if any(x.get('status')!='EMPTY_PROVEN' or x.get('empty_proven') is not True or type(x.get('entries')) is not int or x['entries']!=0 or x.get('signature')!='a(ss)' for x in proofs):raise Refused('CREDENTIAL_SCOPE_NOT_CLOSED')
 return {'unit':unit,'credential_arrays':'PROVEN_EMPTY_CURRENT_SNAPSHOT','original_manifest_unchanged':True}
