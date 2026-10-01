"""Unprivileged V11 renderer. No sudo, publisher, deployment or root execution."""
import hashlib,json,os,signal,stat,subprocess,tempfile
from pathlib import Path
SOURCE=Path('/opt/Tausendunde1nz/_Doku/System_Dokumentation.md')
OUTPUT=Path('/var/lib/tu1nz-privileged-v11-doc-render')
HOOK=Path('/opt/tu1nz_repos/docs/system_manifest/render_kapitel3.sh')
HOOK_SHA='5b338fe604c5a8df22caeec7069c80c8218fb04e1e49fd7199c265c4234634e1'
class Refused(RuntimeError):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def read_regular(path,owner,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=owner or s.st_nlink!=1:raise Refused('INPUT_IDENTITY')
  b=f.read(limit+1);z=os.fstat(f.fileno())
  if len(b)>limit or (s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('INPUT_DRIFT')
 return b

def bounded(argv,cwd,timeout):
 p=subprocess.Popen(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin','HOME':str(cwd),'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','QT_QPA_PLATFORM':'offscreen','XDG_RUNTIME_DIR':str(cwd)})
 try:
  if p.wait(timeout=timeout)!=0:raise Refused('RENDER_FAILED')
 finally:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.wait()

def render(source,output,owner,run=bounded):
 if os.geteuid()==0:raise Refused('ROOT_RENDER_FORBIDDEN')
 import markdown
 source=Path(source);output=Path(output);s=output.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise Refused('OUTPUT_DIRECTORY')
 raw=read_regular(source,owner,8_000_000)
 body=markdown.markdown(raw.decode(),extensions=['extra','toc','tables','sane_lists'])
 html=('<!doctype html><html><head><meta charset="utf-8"><title>System_Dokumentation</title><style>body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; } h1,h2,h3 { margin-top: 1.2em; } code, pre { background:#f6f8fa; padding:2px 4px; }</style></head><body>'+body+'</body></html>').encode()
 with tempfile.TemporaryDirectory(prefix='.render-',dir=output) as d:
  work=Path(d);(work/'document.html').write_bytes(html)
  run(('/usr/bin/wkhtmltopdf','--quiet',str(work/'document.html'),str(work/'document.pdf')),work,120)
  pdf=read_regular(work/'document.pdf',os.geteuid(),32_000_000)
  if not pdf.startswith(b'%PDF-') or b'%%EOF' not in pdf[-1024:]:raise Refused('PDF_FORMAT')
  if digest(read_regular(source,owner,8_000_000))!=digest(raw):raise Refused('SOURCE_DRIFT')
  artifacts={'document.html':html,'document.pdf':pdf}
  manifest={'source_sha256':digest(raw),'sha256':{n:digest(b) for n,b in artifacts.items()}}
  artifacts['manifest.json']=json.dumps(manifest,sort_keys=True).encode()
  # The runtime root-owned publisher refuses hash mixtures or missing files.
  for name,data in artifacts.items():
   f=work/name
   if f.exists():f.unlink()
   fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as o:o.write(data);o.flush();os.fsync(o.fileno())
   os.replace(f,output/name)
  fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 return manifest

def main():
 import sys
 if len(sys.argv)!=1 or os.geteuid()!=1001:raise Refused('SERVICE_IDENTITY')
 os.umask(0o077)
 # This user-controlled hook is deliberately executed only as chatops.
 hook=read_regular(HOOK,1001,1_000_000)
 if digest(hook)!=HOOK_SHA:raise Refused('HOOK_DRIFT')
 render(SOURCE,OUTPUT,0)
 try:bounded(('/bin/bash',str(HOOK)),OUTPUT,60)
 except Refused:print('DOC_KERNEL_HOOK_WARNING')
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit(2)
