"""Frozen memory-only host entry and OFFLINE renderer. Never opens SSH/sudo.

The separate operator must spend the trusted-client attempt BEFORE its one
transport launch. Only this live process's nonce may be signed. No source is
imported from an historical/recovered checkout; public key/hash are pinned.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import shlex

sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_control_recovery_contract as c

PUBLIC_SHA='6b25f4c44c74ef77679e2b83609ab62af3e33a36a7338d4f0046426923e096e5'
MODULES=('tu1nz_control_recovery_contract','tu1nz_control_recovery','tu1nz_control_recovery_entry',
 'tu1nz_s8_execution_contract','tu1nz_s8_admission_channel',
 'tu1nz_s8_historical_kernel','tu1nz_s8_historical_objects')


def remote_argv(packet_sha256):
    """Return only; no connection. Packet must be verified against Source freeze.

    Own GNU timeout only; no foreign process signals. Command-only sudo -k
    does not build/clear another task's cache. Password through operator TTY,
    never arguments/evidence; stdin thereafter carries packet then one grant.
    """
    c.require(len(packet_sha256)==64 and all(x in '0123456789abcdef' for x in packet_sha256),
              'PACKET_PIN_RED')
    command='LC_ALL=C '+shlex.join(['/usr/bin/sudo','-S','-k','-p','', '--',
        '/usr/bin/timeout','--signal=TERM','--kill-after=5s','40s',
        '/usr/bin/python3','-I','-B','-S','-c',BOOTSTRAP,packet_sha256])
    return ['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=10',
        '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ControlMaster=no',
        '-o','ControlPath=none','chatops@100.121.130.51',command]


def serve(capsule,public,*,layout=None,reader=None,writer=None):
    # layout is a library-only synthetic fixture injection, not a host CLI.
    from tu1nz_control_recovery import Session,recover_view
    reader=sys.stdin.buffer if reader is None else reader
    writer=sys.stdout.buffer if writer is None else writer
    layout=c.Layout.production() if layout is None else layout
    session=Session(layout,capsule)
    writer.write(c.canonical({'schema':c.SCHEMA+'_HELLO','body':session.body})+b'\n');writer.flush()
    raw=reader.readline(65537);c.require(0<len(raw)<=65536 and raw.endswith(b'\n'),'GRANT_ENVELOPE_RED')
    grant=json.loads(raw);result=recover_view(layout,capsule,session,grant,public)
    writer.write(c.canonical(result)+b'\n');writer.flush()
    return 0 if result['accepted'] else 2


def packet(root,capsule_raw):
    c.Capsule(capsule_raw)
    public=(root/'config/control-only-recovery/authority-ed25519.pub').read_bytes()
    c.require(c.digest(public)==PUBLIC_SHA,'PUBLIC_KEY_PIN_RED')
    modules={name:base64.b64encode((root/'scripts'/(name+'.py')).read_bytes()).decode() for name in MODULES}
    return c.canonical({'schema':c.SCHEMA+'_MEMORY_PACKET','modules':modules,
        'public':base64.b64encode(public).decode(),'capsule':base64.b64encode(capsule_raw).decode()})


# Packet digest is a separately frozen/operator-verified argument. The memory
# finder refuses ANY other tu1nz module; -I -B -S has no cwd/site imports. No
# persistent source/pycache, systemd, provider or historical checkout module.
BOOTSTRAP = r'''
import base64,hashlib,importlib.abc,importlib.util,json,sys
raw=sys.stdin.buffer.readline(720000001)
assert len(raw)<=720000000 and raw.endswith(b'\n')
assert hashlib.sha256(raw[:-1]).hexdigest()==sys.argv[1]
p=json.loads(raw);assert p['schema']=='TU1NZ_CONTROL_ONLY_RECOVERY_R1_MEMORY_PACKET'
modules={k:base64.b64decode(v,validate=True) for k,v in p['modules'].items()}
class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,name,path=None,target=None):
  if name.startswith('tu1nz_'):
   if name not in modules:raise ImportError('unbound TU1NZ module')
   return importlib.util.spec_from_loader(name,self)
 def create_module(self,spec):return None
 def exec_module(self,module):
  module.__file__='/CONTROL_FROZEN_MEMORY/'+module.__name__+'.py'
  exec(compile(modules[module.__name__],module.__file__,'exec'),module.__dict__)
sys.meta_path.insert(0,Frozen())
import tu1nz_control_recovery_entry as e
import tu1nz_control_recovery_contract as c
assert set(modules)==set(e.MODULES)
public=base64.b64decode(p['public'],validate=True);assert c.digest(public)==e.PUBLIC_SHA
raise SystemExit(e.serve(c.Capsule(base64.b64decode(p['capsule'],validate=True)),public))
'''


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='OFFLINE packet only; not a live launcher')
    parser.add_argument('--capsule',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    from tu1nz_control_recovery_release import save_new
    raw=packet(Path(__file__).resolve().parents[1],args.capsule.read_bytes());save_new(args.output,raw)
    print(json.dumps({'packet_sha256':c.digest(raw),'bytes':len(raw),'host_calls':0,'slot_consumed':False}))
