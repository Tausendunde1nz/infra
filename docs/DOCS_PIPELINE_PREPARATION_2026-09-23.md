# Docs pipeline correction: prerequisite preparation

Authorized scope: valid PDF builder, safe default staging outside Docs Git,
explicit reviewed publication, single systemd WorkingDirectory correction.
No live pipeline or unit change has been made. Both repositories are clean.
All five source files still match docs-path-diagnosis-20260923T162554Z manifest
SHA256 and uid/gid/mode. Existing wkhtmltopdf and pandoc can be reused.
The required file/pdfinfo/pdftotext/pdftoppm tools are absent.

## Minimal dependency plan
Ubuntu24.04 signed repositories through the configured Hetzner Ubuntu mirror:
file1:5.45-3build1, libpoppler134 and poppler-utils24.02.0-1ubuntu9.9.
Unprivileged apt simulation: exactly3 new packages, no upgrade or removal.
No apt update, broad upgrade, recommended packages or daemon restart requested.
NEEDRESTART_MODE=l prevents needrestart automatic service restarts.
Risk: package installation writes system package metadata and tool/library files.
No new network listener or monitoring instance is introduced.

Reviewed executable: /opt/tu1nz_repos/network-hardening-private-2026-09-22/pdf-prerequisites-20260923T163256Z/prepare-pdf-tools.py
SHA256: 5b36f4120242d1d04f9e84aeedd396700349049e399709d15421aeb439d4d461
Its source is preserved below. It rechecks the exact package plan, captures the
full installed package/version map, installs pinned versions, requires existing
versions unchanged and all tools present. On failure it removes only newly
installed approved packages and verifies the original installed-version map.
Package-manager logs/config residuals may remain; no byte-identical dpkg database
rollback is claimed. Later intentional rollback uses apt-get remove only these
three packages after a fresh dependency check; never autoremove unrelated tools.
Private evidence directory0700, result files0600. No credentials are recorded.
A password must be typed by the operator privately in the interactive terminal.

This step does not correct WorkingDirectory or run the existing unsafe builder.
Offline positive/negative pipeline tests, generated PDF visual review, exact
configuration diff, fresh transaction backups and executable file rollback must
all pass and be documented/pushed before pipeline activation. The protected
MyChatBuddy containers, Hetzner and Tailnet remain unchanged.

```python
#!/usr/bin/python3
"""Install only the three approved PDF validation packages; no pipeline activation."""
import os,pathlib,subprocess,json,datetime,hashlib
assert os.geteuid()==0
OUT=pathlib.Path(__file__).resolve().parent
PACKAGES={'file':'1:5.45-3build1','libpoppler134':'24.02.0-1ubuntu9.9','poppler-utils':'24.02.0-1ubuntu9.9'}
def run(*a,env=None):return subprocess.check_output(a,stderr=subprocess.STDOUT,env=env)
def installed():
 lines=run('dpkg-query','-W','-f=${binary:Package} ${db:Status-Abbrev} ${Version}\n').decode().splitlines()
 return {l.split()[0]:l.split()[2] for l in lines if len(l.split())==3 and l.split()[1]=='ii'}
def put(name,data):
 p=OUT/name
 with p.open('xb') as f:f.write(data)
 os.chmod(p,0o600);os.chown(p,1001,1001)
before=installed()
assert not any(p in before or p+':amd64' in before for p in PACKAGES)
put('installed-before.json',json.dumps(before,sort_keys=True).encode())
args=['apt-get','--no-install-recommends','--no-remove','install']+[k+'='+v for k,v in PACKAGES.items()]
plan=run(args[0],'--simulate',*args[1:]).decode()
new={l.split()[1] for l in plan.splitlines() if l.startswith('Inst ')}
assert new==set(PACKAGES) and '0 upgraded, 3 newly installed, 0 to remove' in plan
put('apt-plan.txt',plan.encode())
env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l')
try:
 put('apt-install.txt',run(args[0],'-y',*args[1:],env=env))
 after=installed()
 assert all(after.get(k,after.get(k+':amd64'))==v for k,v in PACKAGES.items())
 assert all(after.get(k)==v for k,v in before.items()),'Existing package changed'
 for tool in ['file','pdfinfo','pdftotext','pdftoppm']:
  assert pathlib.Path('/usr/bin/'+tool).is_file()
 put('COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'packages':PACKAGES,'pipeline_changed':False}).encode())
 print('PDF_PREREQUISITES_COMPLETE',OUT,flush=True)
except BaseException:
 current=installed();new=set(current)-set(before)
 assert all(p.split(':')[0] in PACKAGES for p in new),'Unrelated package drift: no broad rollback'
 if new:put('apt-rollback.txt',run('apt-get','-y','remove',*sorted(new),env=env))
 assert installed()==before
 put('ROLLED_BACK',b'Original installed package/version map restored.\n')
 raise

```
