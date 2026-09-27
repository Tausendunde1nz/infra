"""Offline capsule builder. No activation, SSH, sudo or root writes on import."""
import base64
import hashlib
import json
from pathlib import Path
from loader_v9 import NAMES
from contracts_v9 import MYCB_UNIT_SHA


def build(directory,runtime,baseline_files):
 directory=Path(directory);modules={}
 for name in sorted(NAMES):
  raw=(directory/(name+'.py')).read_bytes();compile(raw,name+'.py','exec')
  modules[name]={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
 payload={'version':9,'modules':modules,'runtime':runtime,'baseline_files':dict(baseline_files)}
 payload['baseline_files']['/etc/systemd/system/mychatbuddy-private-alpha.service']=MYCB_UNIT_SHA
 data=base64.b64encode(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).decode()
 source=('''# Pinned in-memory root capsule; executed only by the separately hash-bound launcher.
import base64,hashlib,json,os,sys
try:
 if os.geteuid()!=0:raise RuntimeError('root required')
 payload=json.loads(base64.b64decode('''+repr(data)+''',validate=True))
 sources={}
 for name,rec in payload['modules'].items():
  raw=base64.b64decode(rec['data'],validate=True)
  if hashlib.sha256(raw).hexdigest()!=rec['sha256']:raise RuntimeError('module digest')
  sources[name]=raw
 ns={'__name__':'capsule_loader'}
 exec(compile(sources['loader_v9'],'<pinned-loader>','exec'),ns)
 sys.dont_write_bytecode=True;sys.meta_path.insert(0,ns['Loader'](sources))
 from prepare_v9 import bootstrap
 print(json.dumps(bootstrap(payload,CAPSULE_SHA256),sort_keys=True))
except BaseException as error:
 print(json.dumps({'status':'REFUSED','error_class':type(error).__name__}))
 raise SystemExit(70)
''').encode()
 compile(source,'<capsule>','exec')
 return source,hashlib.sha256(source).hexdigest()
