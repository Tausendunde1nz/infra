"""Offline immutable capsule builder. Does not install or start anything."""
import base64,hashlib,json
from pathlib import Path
import units
from core import raw,sha,binding_valid
BASIS='e9aeaa406618a90d0b59936905def0e96cb8bf22'
def embedded(modules):
 out='import types,sys\n'
 for name,source in modules:
  encoded=base64.b64encode(source.encode()).decode()
  out+='import base64\n_m=types.ModuleType('+repr(name)+');sys.modules['+repr(name)+']=_m;exec(compile(base64.b64decode('+repr(encoded)+'),'+repr('<pinned:'+name+'>')+',"exec"),_m.__dict__)\n'
 return out

def build(directory,binding):
 d=Path(directory);g=d.parent/'v11_guard_recovery'
 if not binding_valid(binding):raise ValueError('BINDING')
 prelude=(d/'entry.py').read_text()
 modules=[(n,(g/(n+'.py')).read_text()) for n in ('state','runtime','files')]+[(n,(d/(file+'.py')).read_text()) for n,file in [('core','core'),('adapter','adapter')]]
 boot="""
m=checked_manifest(sys.argv[2],'dispatcher.py')
"""
 body="""
import core,adapter
mode=sys.argv[1]
if mode not in ('condition','boot','recover'):raise SystemExit(78)
s=core.Durable();h=adapter.Host(sys.argv[2])
try:
 if mode=='condition':raise SystemExit(0 if core.permit(s,h) else 1)
 if mode=='boot':
  with s.locked():
   s.put('gate.json',{'state':'CLOSED'},True);h.verify_closed(s)
   if s.read('binding.json')!=m['binding']:raise RuntimeError('BOOT_BINDING')
   s.journal()
  raise SystemExit(0)
 if s.read('binding.json')!=m['binding']:raise RuntimeError('MANIFEST_BINDING')
 outcome=core.Dispatcher(s,h).run(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
 raise SystemExit(0 if outcome=='ROLLED_BACK' else 1)
finally:s.close()
"""
 dispatcher=prelude+boot+embedded(modules)+body
 watchdog=prelude+"""
m=checked_manifest(sys.argv[1],'watchdog.py')
import subprocess
r=subprocess.run(('/usr/bin/systemctl','start','--no-block','--','tu1nz-v11-dispatcher.service'),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
raise SystemExit(r.returncode)
"""
 # A closed installer entry is shipped until the publication/rollback adapter
 # passes independent process tests. It cannot accidentally activate artifacts.
 installer=prelude+"""
checked_manifest(sys.argv[1],'installer.py')
raise SystemExit('INSTALLER_PUBLICATION_RECOVERY_NOT_VERIFIED')
"""
 artifacts={'dispatcher.py':dispatcher.encode(),'watchdog.py':watchdog.encode(),'installer.py':installer.encode()}
 for n,b in artifacts.items():compile(b,n,'exec')
 templates={n:s.replace('0'*64,'@MANIFEST_SHA@') for n,s in units.templates('0'*64).items()}
 manifest={'schema':1,'production_admitted':False,'basis':BASIS,'binding':binding,'artifacts':{n:sha(b) for n,b in artifacts.items()},'unit_templates':templates}
 data=raw(manifest);pin=sha(data)
 return {'manifest':data,'manifest_sha256':pin,'artifacts':artifacts,'units':{n:s.replace('@MANIFEST_SHA@',pin).encode() for n,s in templates.items()},'activation_ready':False}
