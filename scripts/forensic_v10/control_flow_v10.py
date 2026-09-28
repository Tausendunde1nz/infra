"""Offline analysis of hash-bound historical sources; never invokes bootstrap."""
import ast
import base64
import hashlib
import json
from pathlib import Path
OLD_SHA='865b33e81db52f497fe834293619ef933f1bfa38ab80b715e91b51c98c342690'

def analyze(capsule):
 raw=Path(capsule).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=OLD_SHA:raise ValueError('historical capsule changed')
 tree=ast.parse(raw);payloads=[]
 for node in ast.walk(tree):
  if isinstance(node,ast.Constant) and isinstance(node.value,str) and len(node.value)>100000:
   try:p=json.loads(base64.b64decode(node.value,validate=True))
   except Exception:continue
   if isinstance(p,dict) and p.get('version')==9 and 'modules' in p:payloads.append(p)
 if len(payloads)!=1:raise ValueError('payload coverage')
 payload=payloads[0];sources={}
 for n,r in payload['modules'].items():
  b=base64.b64decode(r['data'],validate=True)
  if hashlib.sha256(b).hexdigest()!=r['sha256']:raise ValueError('module mismatch')
  sources[n]=b
 t=ast.parse(sources['prepare_v9']);f=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=='bootstrap')
 calls=[]
 for n in ast.walk(f):
  if isinstance(n,ast.Call):calls.append({'line':n.lineno,'call':ast.unparse(n.func)})
 calls.sort(key=lambda x:x['line'])
 text=sources['prepare_v9'].decode();loop_line=next(i for i,l in enumerate(text.splitlines(),1) if 'for name in names:' in l)
 mutations=[x for x in calls if x['call'] in ('create_dir','create_file','private_json','Transaction','Store')]
 if not mutations or not all(x['line']>loop_line for x in mutations):raise ValueError('historical mutation order changed')
 # Include implicit Python import behavior, not just explicit application writes.
 capsule_text=raw.decode();early_import=capsule_text.index('import base64,hashlib,json,os,sys');disable=capsule_text.index('sys.dont_write_bytecode=True')
 if not early_import<disable:raise ValueError('import order changed')
 return {'classification':'MUTATION_REACHABLE_BEFORE_REFUSAL','scope':'Includes possible interpreter .pyc writes; does not assert an actual historical write.','capsule_sha256':OLD_SHA,'module_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in sources.items()},'bootstrap_calls':calls,'fault_loop_line':loop_line,'explicit_host_mutations_after_fault_loop':mutations,'process_local_changes_before_fault':['os.umask','os.chdir'],'implicit_import_cache_write_possible':True,'historical_python_binary_digest':'NOT_BOUND','refused_behavior':'checked raises Refused; loop has no handler; outer capsule emits class and exits70. Bootstrap cleanup finally is after Store creation and unreachable from this loop error.','live_corroboration_required':True}
