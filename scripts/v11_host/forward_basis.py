"""Offline forward adoption and late activation freeze. No Git or host writes.
API facts must come from the authenticated GitHub reader; source bytes are compared
independently. A signed merge need not have a single parent (no history rewrite).
"""
import hashlib,json,re
class Refused(ValueError):pass
REPO='Tausendunde1nz/control'
REF='refs/heads/main'
TARGET='/opt/tu1nz_repos/control-deployment-v11-candidate'
def digest(b):return hashlib.sha256(b).hexdigest()
def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def hexid(x,n):return type(x)==str and re.fullmatch('[a-f0-9]{'+str(n)+'}',x) is not None

def adopt(previous,api,blobs,observation,delta_tests):
 fields={'repository','ref','commit','tree','merge_base','ahead','behind','commit_verified','files'}
 if set(api)!=fields or api['repository']!=REPO or api['ref']!=REF or api['commit_verified'] is not True:raise Refused('PROVENANCE')
 if not all(hexid(api[k],40) for k in ('commit','tree','merge_base')) or not hexid(previous,40):raise Refused('OBJECT_ID')
 if api['merge_base']!=previous or type(api['ahead'])!=int or api['ahead']<=0 or type(api['behind'])!=int or api['behind']!=0:raise Refused('NOT_FORWARD')
 if set(observation)!={'tracked_match','writer_scan_complete','active_writer','index_before','index_after','head','tree'}:raise Refused('OBSERVATION_FIELDS')
 if observation['tracked_match'] is not True or observation['writer_scan_complete'] is not True or observation['active_writer'] is not False:raise Refused('INTEGRITY_OR_WRITER')
 if (observation['head'],observation['tree'])!=(api['commit'],api['tree']):raise Refused('CHECKOUT_BINDING')
 a,b=observation['index_before'],observation['index_after']
 if a!=b or any(a.get(k)!=v for k,v in {'uid':1001,'gid':1001,'mode':0o600,'regular':True,'nlink':1}.items()) or not hexid(a.get('sha256'),64):raise Refused('INDEX')
 rows=api['files']
 if type(rows)!=list or not rows:raise Refused('EMPTY_DELTA')
 paths=[r['path'] for r in rows]
 if len(set(paths))!=len(paths) or set(paths)!=set(blobs) or set(paths)!=set(delta_tests):raise Refused('DELTA_COVERAGE')
 pins={}
 for row in rows:
  if set(row)!={'path','blob','status'} or row['status'] not in ('added','modified','removed'):raise Refused('DELTA_SHAPE')
  name=row['path']
  if not name or name.startswith('/') or any(x in ('','.','..') for x in name.split('/')):raise Refused('PATH')
  proof=delta_tests[name]
  if set(proof)!={'passed','sha256'} or proof['passed'] is not True or not hexid(proof['sha256'],64):raise Refused('DELTA_TEST')
  raw=blobs[name]
  if row['status']=='removed':
   if raw is not None:raise Refused('DELETION_BYTES')
   # No-Delete: removal requires a separate explicit decision, never auto-adopt.
   raise Refused('DELETION_SCOPE')
  if type(raw)!=bytes or not hexid(row['blob'],40) or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=row['blob']:raise Refused('BLOB')
  pins[name]={'git_blob':row['blob'],'sha256':digest(raw)}
 return {'schema':1,'head':api['commit'],'tree':api['tree'],'previous':previous,'source_repository':REPO,'source_ref':REF,'delta':pins,'tests_sha256':digest(encode(delta_tests)),'activation_frozen':False}

def freeze(basis,deployment,refs,now_ns,boot,transaction):
 if basis.get('activation_frozen') is not False:raise Refused('ALREADY_FROZEN')
 required={'path','head','tree','dedicated_gitdir','alternates','tracked_match','index_verified','active_writer','payloads_verified'}
 if set(deployment)!=required or deployment['path']!=TARGET or deployment['head']!=basis['head'] or deployment['tree']!=basis['tree'] or deployment['dedicated_gitdir'] is not True or deployment['alternates'] is not False or deployment['tracked_match'] is not True or deployment['index_verified'] is not True or deployment['active_writer'] is not False or deployment['payloads_verified'] is not True:raise Refused('DEPLOYMENT')
 if set(refs)!={'control/main','infra/control-main'} or refs['control/main']!=basis['head'] or not all(hexid(v,40) for v in refs.values()):raise Refused('REFS')
 if type(now_ns)!=int or now_ns<0 or not re.fullmatch('[a-f0-9-]{36}',boot) or not re.fullmatch('tu1nz-privileged-v11-[a-f0-9]{32}',transaction):raise Refused('FREEZE_BINDING')
 payload={'basis_sha256':digest(encode(basis)),'head':basis['head'],'tree':basis['tree'],'refs':dict(refs),'monotonic_ns':now_ns,'boot':boot,'transaction':transaction}
 return {'activation_frozen':True,'payload':payload,'sha256':digest(encode(payload))}

def validate_frozen(frozen,refs,boot,now_ns):
 if set(frozen)!={'activation_frozen','payload','sha256'} or frozen['activation_frozen'] is not True or digest(encode(frozen['payload']))!=frozen['sha256']:raise Refused('FREEZE_HASH')
 p=frozen['payload']
 if p['refs']!=refs or p['boot']!=boot or type(now_ns)!=int or not 0<=now_ns-p['monotonic_ns']<=300_000_000_000:raise Refused('ACTIVATION_MANIFEST_INVALIDATED')
 return True
