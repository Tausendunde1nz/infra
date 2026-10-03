"""Offline self-contained artifact builder. Never installs or starts code."""
import base64
from pathlib import Path

def embedded(rows):
 out='import types,sys,base64\n'
 for name,data in rows:
  out+='_m=types.ModuleType('+repr(name)+');sys.modules['+repr(name)+']=_m;exec(compile(base64.b64decode('+repr(base64.b64encode(data).decode())+'),'+repr('<pinned:'+name+'>')+',"exec"),_m.__dict__)\n'
 return out

def modules(directory):
 d=Path(directory);g=d.parent/'v11_guard_recovery';old=d.parent/'v11_dispatcher'
 return [(n,(g/(n+'.py')).read_bytes()) for n in ('state','runtime','files')]+[(n,(old/(n+'.py')).read_bytes()) for n in ('core','units','publication','systemd_adapter')]+[(n,(d/(n+'.py')).read_bytes()) for n in ('anchor','worker','manager','base_host','phase0','attestation','bootstrap','phase1','install','host','guard_verifier')]

def build(directory,profile):
 if profile not in ('production','validation'):raise ValueError('PROFILE')
 prelude='import os,sys\nif os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode:raise SystemExit(78)\nos.umask(0o077)\nos.environ.clear();os.environ.update({"PATH":"/usr/bin:/bin","LC_ALL":"C","HOME":"/var/empty","PYTHONDONTWRITEBYTECODE":"1"})\n'
 full=modules(directory)
 common=prelude+embedded(full)+'\nPROFILE='+repr(profile)+'\n'
 retained=prelude+embedded([(n,b) for n,b in full if n in ('anchor','worker','manager','base_host')])+'\nPROFILE='+repr(profile)+'\n'
 if profile=='production':
  retained+='raise SystemExit(78) # Inner transaction admission remains closed.\n'
  common+='raise SystemExit(78) # No production recovery before inner binding.\n'
 anchor=retained+"""
import anchor,base_host,manager
if len(sys.argv)!=3 or sys.argv[1] not in ('recover','condition'):raise SystemExit(78)
p=manager.profile(PROFILE)
if sys.argv[0]!=p['root']+'/anchor.py':raise SystemExit(78)
s=anchor.Store(p['root'],validation=PROFILE=='validation')
try:
 if anchor.digest(s.read('base.json'))!=sys.argv[2]:raise anchor.Refused('BASE_PIN')
 if sys.argv[1]=='condition':
  # Phase-0 rollback contract is CLOSED. This entry grants no application
  # activation, including on terminal rollback or an elapsed deadline.
  s.base();raise SystemExit(1)
 result=anchor.Anchor(s,base_host.RootHost(s,PROFILE)).run()
 print(result)
 raise SystemExit(0 if result in ('RECOVERY_BASE_READY',anchor.TERMINAL,'SECURED_STOP') else 1)
finally:s.close()
"""
 worker=common+"""
import host,anchor
if len(sys.argv)!=3 or sys.argv[1] not in ('recover','verify') or not anchor.pin(sys.argv[2]):raise SystemExit(78)
print(anchor.encode(host.recover_entry(PROFILE,sys.argv[2],sys.argv[1])).decode(),end='')
"""
 for name,source in [('anchor.py',anchor),('worker.py',worker)]:compile(source,name,'exec')
 return {'anchor':anchor.encode(),'worker':worker.encode(),'profile':profile,'production_activation_ready':False}
