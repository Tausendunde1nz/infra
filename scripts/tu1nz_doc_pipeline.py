#!/usr/bin/python3
"""Safe daily operational summary. Default stage never calls Git."""
import argparse,datetime,fcntl,hashlib,html,json,os,pathlib,pwd,re,subprocess,tempfile,urllib.request
REPO=pathlib.Path('/opt/tu1nz_repos/docs')
ORIGIN='git@github.com:Tausendunde1nz/docs.git'
STAGING=pathlib.Path('/opt/tu1nz_repos/doc-staging')
SERVICES=('tailscaled','ssh','nginx','docker','fail2ban')
SECRET=re.compile(r'-----BEGIN .*PRIVATE KEY|(?:password|token|secret|authorization|cookie)\s*[:=]|\bgh[pousr]_[A-Za-z0-9]{12,}|\bAKIA[0-9A-Z]{16}',re.I)
def run(*args,env=None):
 return subprocess.check_output(args,stderr=subprocess.PIPE,env=env,timeout=60)
def require(test,message):
 if not test:raise ValueError(message)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def private_write(p,data):
 with p.open('xb') as f:f.write(data)
 os.chmod(p,0o600)
def text_for(data):
 require(set(data)=={'date','server','services','monitoring'},'Unexpected input fields')
 require(re.fullmatch(r'\d{4}-\d{2}-\d{2}',data['date']) is not None,'Invalid date')
 datetime.date.fromisoformat(data['date'])
 require(data['server']=='ubuntu-8gb-nbg1-2','Unexpected server')
 require(set(data['services'])==set(SERVICES),'Unexpected services')
 require(all(v in ('active','inactive','failed','activating','deactivating') for v in data['services'].values()),'Unexpected service state')
 require(set(data['monitoring'])=={'node','cadvisor'},'Unexpected monitoring fields')
 require(all(v in ('up','down','unknown') for v in data['monitoring'].values()),'Unexpected target state')
 lines=['TU1NZ - Daily operational summary','Date (UTC): '+data['date'],'Server: '+data['server'],'Service states']
 lines += [k+': '+data['services'][k] for k in SERVICES]
 lines += ['Monitoring targets']+[k+': '+data['monitoring'][k] for k in ('node','cadvisor')]
 lines += ['Scope: selected service and scrape states only.','This report is not a complete system audit.','No credentials, environment files or application content are collected.']
 text='\n'.join(lines)+'\n'
 require(not SECRET.search(text),'Secret pattern blocked')
 return text

def collect():
 data={'date':datetime.datetime.now(datetime.timezone.utc).date().isoformat(),'server':run('hostname').decode().strip(),'services':{},'monitoring':{}}
 for name in SERVICES:
  data['services'][name]=run('systemctl','show',name+'.service','--property=ActiveState','--value').decode().strip()
 with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets',timeout=5) as response:obj=json.load(response)
 for t in obj['data']['activeTargets']:
  job=t.get('labels',{}).get('job')
  if job in ('node','cadvisor'):
   require(job not in data['monitoring'],'Duplicate monitoring target')
   data['monitoring'][job]=t['health']
 text_for(data)
 return data

def validate(folder):
 folder=pathlib.Path(folder)
 require(not folder.is_symlink(),'Symlink staging blocked')
 manifest=folder/'manifest.json'
 require(manifest.is_file() and not manifest.is_symlink(),'Missing manifest')
 m=json.loads(manifest.read_text())
 require(set(m)=={'data','pdf_sha256','filename'},'Unexpected manifest')
 text=text_for(m['data'])
 name='System_Dokumentation_Tausendunde1nz_'+m['data']['date']+'.pdf'
 require(m['filename']==name,'Unexpected filename')
 pdf=folder/name
 require(pdf.is_file() and not pdf.is_symlink(),'Missing PDF')
 require(digest(pdf)==m['pdf_sha256'],'PDF checksum mismatch')
 require(pdf.read_bytes().startswith(b'%PDF-'),'Invalid PDF signature')
 require(b'PDF document' in run('file','-b',str(pdf)),'file rejected PDF')
 info=run('pdfinfo',str(pdf)).decode()
 require(re.search(r'^Pages:\s+1\s*$',info,re.M) is not None,'Expected exactly one page')
 extracted=run('pdftotext','-layout',str(pdf),'-').decode()
 require(extracted.strip() and not SECRET.search(extracted),'Empty or suspicious PDF text')
 require(' '.join(extracted.split())==' '.join(text.split()),'PDF content mismatch')
 # Temporary render: never overwrite a previous artifact.
 with tempfile.TemporaryDirectory(prefix='render-',dir=folder) as tmp:
  run('pdftoppm','-f','1','-singlefile','-scale-to','1200','-png',str(pdf),tmp+'/page')
  png=pathlib.Path(tmp+'/page.png').read_bytes()
  require(png.startswith(b'\x89PNG') and len(png)>5000,'Empty or invalid render')
 return m,pdf

def pdf_bytes(text):
 """One-page ASCII report; fixed safe layout, no active or external PDF content."""
 lines=text.splitlines()
 require(1<=len(lines)<=25 and all(0<len(x)<=100 and x.isascii() for x in lines),'Report layout bounds exceeded')
 stream=[]
 for i,line in enumerate(lines):
  escaped=line.replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
  size=18 if i==0 else 11
  stream.append('BT /F1 %d Tf 40 %d Td (%s) Tj ET'%(size,790-i*23,escaped))
 content=('\n'.join(stream)+'\n').encode('ascii')
 objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'endstream']
 output=bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\x00\n');offsets=[0]
 for i,obj in enumerate(objects,1):
  offsets.append(len(output));output.extend(str(i).encode()+b' 0 obj\n'+obj+b'\nendobj\n')
 xref=len(output);output.extend(b'xref\n0 6\n0000000000 65535 f \n')
 for offset in offsets[1:]:output.extend(('%010d 00000 n \n'%offset).encode())
 output.extend(b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n')
 return bytes(output)

def stage(base=STAGING,data=None):
 base=pathlib.Path(base)
 require(not base.is_symlink(),'Symlink staging base blocked')
 base.mkdir(mode=0o700,exist_ok=True);os.chmod(base,0o700)
 folder=pathlib.Path(tempfile.mkdtemp(prefix='stage-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-',dir=base));os.chmod(folder,0o700)
 data=collect() if data is None else data
 text=text_for(data)
 name='System_Dokumentation_Tausendunde1nz_'+data['date']+'.pdf';pdf=folder/name
 private_write(pdf,pdf_bytes(text))
 private_write(folder/'manifest.json',json.dumps({'data':data,'filename':name,'pdf_sha256':digest(pdf)},sort_keys=True,indent=2).encode())
 validate(folder)
 return folder

def repo_check(repo,origin):
 def git(*a):return run('git','-C',str(repo),*a).decode().strip()
 require(git('remote','get-url','origin')==origin,'Wrong repository remote')
 require(git('branch','--show-current')=='main','Expected main branch')
 require(not git('status','--porcelain','--untracked-files=all'),'Dirty repository blocked')
 head=git('rev-parse','HEAD');remote=git('ls-remote','origin','refs/heads/main').split()
 require(remote and remote[0]==head,'Remote drift or pending commit blocked')
 return head

def publish(folder,approved_hash,repo=REPO,origin=ORIGIN,push=True):
 require(pwd.getpwuid(os.getuid()).pw_name=='chatops','Publish only as chatops')
 m,pdf=validate(folder)
 require(m['pdf_sha256']==approved_hash,'Explicit reviewed hash required')
 require(m['data']['date']==datetime.datetime.now(datetime.timezone.utc).date().isoformat(),'Stale report date')
 repo=pathlib.Path(repo);head=repo_check(repo,origin)
 target=repo/m['filename']
 if target.exists():
  require(not target.is_symlink(),'Symlink target blocked')
  old=run('pdftotext','-layout',str(target),'-').decode()
  if ' '.join(old.split())==' '.join(text_for(m['data']).split()):return 'UNCHANGED'
 # All prerequisites passed. Back up any previous document with a fresh name.
 backup=pathlib.Path(tempfile.mkdtemp(prefix='publish-backup-',dir=pathlib.Path(folder)));os.chmod(backup,0o700)
 existed=target.exists();mode=target.stat().st_mode&0o777 if existed else 0o644
 if existed:private_write(backup/'original.pdf',target.read_bytes())
 private_write(backup/'before.json',json.dumps({'head':head,'existed':existed,'mode':mode,'filename':m['filename']}).encode())
 committed=False
 def git(*a):return run('git','-C',str(repo),*a).decode().strip()
 try:
  require(repo_check(repo,origin)==head,'Concurrent repository change')
  fd,name=tempfile.mkstemp(prefix='.tu1nz-pdf-',dir=repo)
  with os.fdopen(fd,'wb') as f:f.write(pdf.read_bytes());f.flush();os.fsync(f.fileno())
  os.chmod(name,mode);os.replace(name,target)
  require(digest(target)==approved_hash,'Installed PDF drift')
  # Never stage foreign files. Abort if any other working-tree path appeared.
  entries=run('git','-C',str(repo),'status','--porcelain','--untracked-files=all').decode().splitlines()
  require(all(e[3:]==m['filename'] for e in entries),'Unexpected repository changes')
  require(not git('diff','--cached','--name-only'),'Foreign staged changes')
  git('add','-f','--',m['filename'])
  require(git('diff','--cached','--name-only')==m['filename'],'Unexpected staged files')
  git('diff','--cached','--check')
  require(git('rev-parse','HEAD')==head,'Concurrent HEAD change')
  git('commit','-m','docs: validated daily operational summary '+m['data']['date']);committed=True
  commit=git('rev-parse','HEAD')
  require(git('diff-tree','--no-commit-id','--name-only','-r',commit)==m['filename'],'Commit scope mismatch')
  require(hashlib.sha256(run('git','-C',str(repo),'show',commit+':'+m['filename'])).hexdigest()==approved_hash,'Committed PDF mismatch')
  if push:
   git('push','origin','HEAD:refs/heads/main')
   require(git('ls-remote','origin','refs/heads/main').split()[0]==commit,'Push verification failed')
  return ('PUSHED ' if push else 'COMMITTED_NOT_PUSHED ')+commit
 except BaseException:
  if not committed:
   # Do not erase concurrent work. Restore only our unchanged generated PDF.
   if target.exists() and digest(target)==approved_hash:
    if existed:target.write_bytes((backup/'original.pdf').read_bytes());os.chmod(target,mode)
    else:target.unlink()
   if git('diff','--cached','--name-only')==m['filename']:git('restore','--staged','--',m['filename'])
  # A push failure leaves a reviewed local commit for diagnosis, never resets HEAD.
  raise

def main():
 parser=argparse.ArgumentParser()
 group=parser.add_mutually_exclusive_group(required=True)
 group.add_argument('--stage',action='store_true');group.add_argument('--validate',type=pathlib.Path);group.add_argument('--publish',type=pathlib.Path)
 parser.add_argument('--reviewed-sha256')
 a=parser.parse_args()
 require(not STAGING.is_symlink(),'Symlink staging base blocked')
 STAGING.mkdir(mode=0o700,exist_ok=True)
 require(STAGING.stat().st_uid==os.getuid(),'Wrong staging owner')
 os.chmod(STAGING,0o700)
 lock=STAGING/'pipeline.lock'
 with lock.open('a') as f:
  os.chmod(lock,0o600);fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if a.stage:print('STAGED',stage())
  elif a.validate:print('VALIDATED',validate(a.validate)[0]['pdf_sha256'])
  else:print(publish(a.publish,a.reviewed_sha256))
if __name__=='__main__':main()
