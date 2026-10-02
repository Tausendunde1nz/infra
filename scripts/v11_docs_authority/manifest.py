"""Deterministic source authority. No measured file can add itself to the authority."""
import hashlib,json,re,unicodedata
SCHEMA=1
GENERATOR='tu1nz-docs-authority-1'
MAX_BYTES=4_000_000
MAX_FILES=20000
class Refused(RuntimeError):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n'
def name(p):
 if type(p) is not str or not p or p.startswith(('/','-')) or '\\' in p or len(p)>4096 or any(unicodedata.category(c).startswith('C') for c in p):raise Refused('PATH')
 if any(s in ('','.','..') or s.startswith('-') for s in p.split('/')):raise Refused('PATH_COMPONENT')
 return p

def source(repository,commit,tree,rows,created_utc):
 if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",created_utc):raise Refused("METADATA_TIME")
 if repository!='Tausendunde1nz/docs' or not all(re.fullmatch('[0-9a-f]{40}',v) for v in (commit,tree)):raise Refused('SOURCE_PIN')
 if not rows or len(rows)>MAX_FILES:raise Refused('SOURCE_SIZE')
 entries=[];seen=set()
 for path,mode,blob,data in rows:
  name(path)
  if path in seen or mode not in ('100644','100755') or type(data) is not bytes:raise Refused('TREE_ENTRY')
  if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=blob:raise Refused('GIT_BLOB')
  entries.append({'path':path,'type':'regular','sha256':digest(data),'git_blob':blob,'git_mode':mode});seen.add(path)
 return {'schema':SCHEMA,'generator':GENERATOR,'kind':'SOURCE_MANIFEST','repository':repository,'commit':commit,'tree':tree,'metadata':{'created_utc':created_utc,'timestamp_is_trust_anchor':False},'entries':sorted(entries,key=lambda x:x['path'])}

def approve(src,generated):
 # No generated outputs have an approved reproducibility contract in this version.
 if generated!={'schema':1,'kind':'GENERATED_MANIFEST','entries':[]}:raise Refused('UNAPPROVED_GENERATOR')
 if src.get('schema')!=SCHEMA or src.get('generator')!=GENERATOR or src.get('kind')!='SOURCE_MANIFEST':raise Refused('SOURCE_SCHEMA')
 result={**src,'kind':'APPROVED_AUTHORITY','source_manifest_sha256':digest(canonical(src)),'generated_manifest_sha256':digest(canonical(generated))}
 validate(result)
 return result

def validate(obj):
 required={'schema','generator','kind','repository','commit','tree','metadata','entries','source_manifest_sha256','generated_manifest_sha256'}
 if type(obj) is not dict or set(obj)!=required or obj['schema']!=SCHEMA or obj['generator']!=GENERATOR or obj['kind']!='APPROVED_AUTHORITY' or obj['repository']!='Tausendunde1nz/docs':raise Refused('MANIFEST_SCHEMA')
 if not all(type(obj[k]) is str and re.fullmatch('[0-9a-f]{40}',obj[k]) for k in ('commit','tree')):raise Refused('PIN')
 if type(obj['metadata']) is not dict or set(obj['metadata'])!={'created_utc','timestamp_is_trust_anchor'} or obj['metadata']['timestamp_is_trust_anchor'] is not False or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',obj['metadata']['created_utc']):raise Refused('METADATA')
 if not isinstance(obj['entries'],list) or not 1<=len(obj['entries'])<=MAX_FILES:raise Refused('ENTRIES')
 seen=set()
 for e in obj['entries']:
  if type(e)is not dict or set(e)!={'path','type','sha256','git_blob','git_mode'} or e['type']!='regular' or e['git_mode'] not in ('100644','100755'):raise Refused('ENTRY_TYPE')
  p=name(e['path'])
  if p in seen or not re.fullmatch('[0-9a-f]{64}',e['sha256']) or not re.fullmatch('[0-9a-f]{40}',e['git_blob']):raise Refused('ENTRY_HASH_OR_DUPLICATE')
  seen.add(p)
 if obj['entries']!=sorted(obj['entries'],key=lambda e:e['path']):raise Refused('ORDER')
 src={k:v for k,v in obj.items() if k not in ('source_manifest_sha256','generated_manifest_sha256')};src['kind']='SOURCE_MANIFEST'
 if digest(canonical(src))!=obj['source_manifest_sha256'] or digest(canonical({'schema':1,'kind':'GENERATED_MANIFEST','entries':[]}))!=obj['generated_manifest_sha256']:raise Refused('CHAIN_HASH')
 return obj

def parse(raw,expected,commit,tree):
 if type(raw)is not bytes or not raw or len(raw)>MAX_BYTES or digest(raw)!=expected:raise Refused('AUTHORITY_BYTES')
 def pairs(items):
  d={}
  for k,v in items:
   if k in d:raise Refused('DUPLICATE_JSON_KEY')
   d[k]=v
  return d
 obj=validate(json.loads(raw,object_pairs_hook=pairs))
 if obj['commit']!=commit or obj['tree']!=tree or canonical(obj)!=raw:raise Refused('PIN_OR_ENCODING')
 return obj
