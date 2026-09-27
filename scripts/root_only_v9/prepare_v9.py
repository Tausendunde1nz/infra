"""Pinned in-memory bootstrap. Calling bootstrap is a later privileged activation.

This file is inert on import and has no general-purpose command line interface.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from policy_v9 import Refused
from contracts_v9 import watchdog_service,watchdog_timer,QUARANTINE_HASHES,SOCKET_UNIT_SHA,DOCKER_UNIT_SHA
from files_v9 import safe_chain,bytes_of
from host_v9 import Host,ROOT,PACKAGE,BROKER_ROOT,READ_TARGETS,file_snapshot,private_json,BROKER,HELPER,MYCB_UNIT
from candidates_v9 import compile_candidates,record
from transaction_v9 import Store,Transaction
from command_v9 import checked
from loader_v9 import NAMES
import tu1nz_codex_broker_v9 as broker
from sudo_candidate_v9 import BASELINES

DIRECTORIES=(ROOT,PACKAGE,BROKER_ROOT,BROKER_ROOT/'docker')
UNITS=Path('/etc/systemd/system')
WORKER='''[Unit]
Description=TU1NZ pinned root-only Docker migration
After=local-fs.target docker.service
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
WorkingDirectory=/
ExecStart=/usr/bin/python3 -I -S /usr/local/libexec/tu1nz-root-only-v9/entry_v9.py worker
TimeoutStartSec=50min
TimeoutStopSec=600
KillMode=control-group
Restart=no
'''


def create_dir(path,mode=0o700):
 safe_chain(path.parent)
 if path.exists() or path.is_symlink():raise Refused('bootstrap directory already exists')
 os.mkdir(path,mode);os.chmod(path,mode)
 safe_chain(path)


def create_file(path,data,mode=0o600):
 safe_chain(path.parent)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)


def helper_source(loader_source):
 # All package bytes are checked and loaded into memory before interpretation.
 suffix=b'''\nif __name__=='__main__':
 import json
 import sys
 try:
  if os.geteuid()!=0 or Path(__file__)!=Path('/usr/local/sbin/tu1nz-mychatbuddy-lifecycle'):raise RuntimeError('installed root helper only')
  manifest=json.loads(protected_read(ROOT/'manifest.json'))
  install(manifest['modules'])
  from lifecycle_v9 import main
  raise SystemExit(main(sys.argv[1:]))
 except Exception as e:
  print(json.dumps({'status':'DENIED','error_class':type(e).__name__}))
  raise SystemExit(77)
'''
 return b'#!/usr/bin/env -S /usr/bin/python3 -I -S\n'+loader_source+suffix


def validate_payload(payload):
 if set(payload)!={'version','modules','runtime','baseline_files'} or payload['version']!=9 or set(payload['modules'])!=NAMES:raise Refused('bootstrap schema')
 modules={}
 for name,entry in payload['modules'].items():
  if set(entry)!={'data','sha256'}:raise Refused('module record')
  raw=base64.b64decode(entry['data'],validate=True)
  if len(raw)>500_000 or hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise Refused('module content')
  compile(raw,str(PACKAGE/(name+'.py')),'exec',dont_inherit=True)
  modules[name]=raw
 return modules


def bootstrap(payload,capsule_sha256):
 if os.geteuid()!=0:raise Refused('root bootstrap required')
 os.umask(0o077);os.chdir('/')
 modules=validate_payload(payload)
 if any(p.exists() or p.is_symlink() for p in DIRECTORIES):raise Refused('preexisting migration directory')
 unit_paths=[UNITS/n for n in ('tu1nz-root-only-v9.service','tu1nz-root-only-v9-watchdog.service','tu1nz-root-only-v9-watchdog.timer')]
 if any(p.exists() or p.is_symlink() for p in unit_paths):raise Refused('preexisting migration unit')
 # daemon-reload is global: reject any pending foreign loaded-unit change.
 raw=checked(['/usr/bin/systemctl','list-units','--all','--plain','--no-legend','--no-pager']).decode()
 names=[line.split()[0] for line in raw.splitlines() if line.split()]
 for name in names:
  flag=checked(['/usr/bin/systemctl','show',name,'-p','NeedDaemonReload','--value']).strip()
  if flag!=b'no':raise Refused('pending foreign systemd reload')
 # Fresh originals are gathered before any system file is changed. They remain
 # only in root memory until the private evidence directory is safely created.
 originals={p:file_snapshot(p) for p in READ_TARGETS}
 baseline=dict(payload['baseline_files']);baseline.update(BASELINES);baseline.update(QUARANTINE_HASHES)
 baseline['/usr/lib/systemd/system/docker.socket']=SOCKET_UNIT_SHA;baseline['/usr/lib/systemd/system/docker.service']=DOCKER_UNIT_SHA
 for p,h in baseline.items():
  rec=originals[p] if p in originals else file_snapshot(p)
  if rec.get('sha256')!=h:raise Refused('bootstrap baseline drift: '+p)
 for p in (BROKER,HELPER,MYCB_UNIT):
  if p!=MYCB_UNIT and originals[p]!={'absent':True}:raise Refused('preexisting broker/helper')
 helper=helper_source(modules['loader_v9'])
 candidates=compile_candidates(originals,modules['tu1nz_codex_broker_v9'],helper,broker.sudoers().encode())
 manifest={'version':9,'capsule_sha256':capsule_sha256,'modules':{n:hashlib.sha256(v).hexdigest() for n,v in modules.items()},
  'runtime':payload['runtime'],'baseline_files':baseline,'candidates':candidates,'final_sudo':record(broker.sudoers(temporary=False).encode(),0o440)}
 # Initial creation records absence; no existing directory or foreign file is
 # overwritten. Failed early bootstrap leaves private evidence, never grants.
 optional_directories={str(PACKAGE.parent):not PACKAGE.parent.exists(),str(UNITS/'docker.socket.d'):not (UNITS/'docker.socket.d').exists()}
 create_dir(ROOT)
 if not PACKAGE.parent.exists():create_dir(PACKAGE.parent,0o755)
 else:safe_chain(PACKAGE.parent)
 for path in DIRECTORIES[1:]:create_dir(path)
 private_json(ROOT/'bootstrap-original.json',{'files':originals,'absent_directories':[str(p) for p in DIRECTORIES],'absent_units':[str(p) for p in unit_paths],'optional_directory_absence':optional_directories})
 for name,raw in modules.items():create_file(PACKAGE/(name+'.py'),raw,0o600)
 create_file(PACKAGE/'manifest.json',json.dumps(manifest,sort_keys=True).encode())
 create_file(BROKER_ROOT/'lock',b'')
 create_file(BROKER_ROOT/'docker/config.json',b'{}\n')
 binaries={v[0] for v in broker.COMMANDS.values()}
 broker_manifest={'program_sha256':hashlib.sha256(modules['tu1nz_codex_broker_v9']).hexdigest(),
  'programs':{p:broker.program_digest(p) for p in binaries},'mychatbuddy_unit_sha256':candidates[MYCB_UNIT]['sha256']}
 create_file(BROKER_ROOT/'manifest.json',json.dumps(broker_manifest,sort_keys=True).encode())
 definitions=(WORKER,watchdog_service(),watchdog_timer())
 for path,text in zip(unit_paths,definitions):create_file(path,text.encode(),0o644)
 create_file(PACKAGE/'tu1nz-root-only-v9-watchdog.service',watchdog_service().encode())
 # The only optional system directory; root-owned, no permissive ancestor/ACL.
 drop=UNITS/'docker.socket.d'
 if not drop.exists():create_dir(drop,0o755)
 else:safe_chain(drop)
 checked(['/usr/bin/systemctl','daemon-reload'])
 store=Store(ROOT)
 try:
  tx=Transaction(store,Host(store,manifest));tx.begin(Path('/proc/sys/kernel/random/boot_id').read_text().strip(),2700,capsule_sha256)
 finally:store.close()
 checked(['/usr/bin/systemctl','start','--no-block','tu1nz-root-only-v9.service'])
 return {'status':'WORKER_STARTED','capsule_sha256':capsule_sha256}
