#!/usr/bin/python3
"""Reviewed privileged transaction; preserves old files until final validation."""
import datetime,hashlib,json,os,pathlib,signal,subprocess,tempfile,time
BASE=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')
W=pathlib.Path('/opt/tu1nz_repos/worktrees/network-hardening-2026-09-22')
BASELINE=BASE/'docs-path-diagnosis-20260923T162554Z/manifest.json'
ENGINE_SHA='a24158656df175acc935433345b59e8a3267b8cec37a633ee89e486f9eaeb788'
WRAPPER_SHA='20ca16f38a71b7b83e8a2bfbc0eb71d6d840a592400f6d5f1739d16a843957cd'
def sha(data):return hashlib.sha256(data).hexdigest()
def run(*a):return subprocess.check_output(a,stderr=subprocess.STDOUT,timeout=120)
def put(folder,name,data):
 p=folder/name
 with p.open('xb') as f:f.write(data)
 os.chmod(p,0o600);os.chown(p,1001,1001)
def atomic(path,data,mode,uid,gid):
 fd,tmp=tempfile.mkstemp(prefix='.tu1nz-doc-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,mode);os.chown(tmp,uid,gid);os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def restore(out):
 manifest=json.loads((out/'manifest.json').read_text())
 for e in reversed(manifest):
  p=pathlib.Path(e['path'])
  if not e['changed']:continue
  if p.exists():assert sha(p.read_bytes()) in [e['candidate_sha'],e.get('sha')], 'Concurrent live edit: refuse overwrite'
  if e['existed']:
   data=(out/e['backup']).read_bytes();assert sha(data)==e['sha'];atomic(p,data,e['mode'],e['uid'],e['gid'])
  elif p.exists():p.unlink()
 run('systemctl','daemon-reload')
 for e in manifest:
  p=pathlib.Path(e['path'])
  if e['existed']:
   st=p.stat();assert sha(p.read_bytes())==e['sha'] and (st.st_uid,st.st_gid,st.st_mode&0o777)==(e['uid'],e['gid'],e['mode'])
  else:assert not p.exists()
 assert run('systemctl','show','tu1nz-doc.service','--property=WorkingDirectory','--value').strip()==b'/opt/tu1nz_repos/docs_repo'
 put(out,'ROLLED_BACK.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'configuration_restored':True,'git_history_reset':False}).encode())
 print('DOC_PIPELINE_ROLLED_BACK',out,flush=True)
def main():
 assert os.geteuid()==0
 import sys
 if len(sys.argv)==3 and sys.argv[1]=='--rollback':restore(pathlib.Path(sys.argv[2]));return
 assert len(sys.argv)==1
 engine=(W/'scripts/tu1nz_doc_pipeline.py').read_bytes();wrapper=(W/'scripts/tu1nz_doc_safe_wrapper.sh').read_bytes()
 assert sha(engine)==ENGINE_SHA and sha(wrapper)==WRAPPER_SHA
 originals=json.loads(BASELINE.read_text())
 for e in originals:
  p=pathlib.Path(e['source']);st=p.stat();assert sha(p.read_bytes())==e['sha256'] and (st.st_uid,st.st_gid,oct(st.st_mode&0o777))==(e['uid'],e['gid'],e['mode'])
 assert run('systemctl','show','tu1nz-doc.service','--property=ActiveState','--value').strip() in [b'failed',b'inactive']
 assert run('systemctl','is-active','tu1nz-doc.timer').strip()==b'active'
 def git(*a):return run('runuser','-u','chatops','--','git','-C','/opt/tu1nz_repos/docs',*a).strip()
 assert git('status','--porcelain')==b''
 beforehead=git('rev-parse','HEAD');assert git('ls-remote','origin','refs/heads/main').split()[0]==beforehead
 out=BASE/('docs-transaction-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));out.mkdir(mode=0o700);os.chmod(out,0o700);os.chown(out,1001,1001)
 targets={pathlib.Path('/usr/local/bin/tu1nz_doc_pipeline.py'):engine,pathlib.Path('/usr/local/bin/tu1nz_doc_auto.sh'):wrapper,pathlib.Path('/usr/local/bin/tu1nz_doc_update.sh'):wrapper}
 enginepath=pathlib.Path('/usr/local/bin/tu1nz_doc_pipeline.py');assert not os.path.lexists(enginepath)
 drop=pathlib.Path('/etc/systemd/system/tu1nz-doc.service.d/override.conf')
 raw=drop.read_bytes();assert raw.count(b'WorkingDirectory=/opt/tu1nz_repos/docs_repo')==1
 targets[drop]=raw.replace(b'WorkingDirectory=/opt/tu1nz_repos/docs_repo',b'WorkingDirectory=/opt/tu1nz_repos/docs')
 paths=list(targets)+[pathlib.Path('/etc/systemd/system/tu1nz-doc.service'),pathlib.Path('/etc/systemd/system/tu1nz-doc.timer')]
 manifest=[]
 for i,p in enumerate(paths):
  assert not p.is_symlink();entry={'path':str(p),'existed':p.exists(),'changed':p in targets,'candidate_sha':sha(targets[p]) if p in targets else None}
  if p.exists():
   st=p.stat();data=p.read_bytes();entry.update(backup=str(i)+'.original',sha=sha(data),mode=st.st_mode&0o777,uid=st.st_uid,gid=st.st_gid);put(out,entry['backup'],data)
  manifest.append(entry)
 put(out,'manifest.json',json.dumps(manifest,indent=2).encode())
 put(out,'rollback.py',pathlib.Path(__file__).read_bytes())
 # Offline round-trip in an isolated fixture; exact original bytes and mode.
 with tempfile.TemporaryDirectory(dir=out,prefix='rollback-proof-') as tmp:
  for i,e in enumerate(manifest):
   if not e['changed']:continue
   q=pathlib.Path(tmp)/str(i);q.write_bytes(targets[pathlib.Path(e['path'])])
   if e['existed']:
    q.write_bytes((out/e['backup']).read_bytes());os.chmod(q,e['mode']);assert sha(q.read_bytes())==e['sha'] and q.stat().st_mode&0o777==e['mode']
   else:q.unlink();assert not q.exists()
 put(out,'OFFLINE_ROLLBACK_PASSED',b'All original bytes and modes restored in fixture.\n')
 def stop(signum,frame):raise RuntimeError('Interrupted')
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGHUP,stop);signal.signal(signal.SIGINT,stop)
 changed=False
 try:
  for e in manifest:
   if not e['changed']:continue
   p=pathlib.Path(e['path']);changed=True
   atomic(p,targets[p],e.get('mode',0o755),e.get('uid',0),e.get('gid',0))
  run('systemctl','daemon-reload')
  assert run('systemctl','show','tu1nz-doc.service','--property=WorkingDirectory','--value').strip()==b'/opt/tu1nz_repos/docs'
  put(out,'service-start.txt',run('systemctl','start','tu1nz-doc.service'))
  status=run('systemctl','show','tu1nz-doc.service','--property=Result,ExecMainStatus');put(out,'service-status.txt',status)
  assert b'Result=success' in status and b'ExecMainStatus=0' in status
  assert git('rev-parse','HEAD')==beforehead and git('status','--porcelain')==b''
  assert git('ls-remote','origin','refs/heads/main').split()[0]==beforehead
  put(out,'WAITING_FOR_VALIDATION.json',json.dumps({'head':beforehead.decode(),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'timeout_seconds':1800}).encode())
  print('WAITING_FOR_DOC_VALIDATION',out,flush=True)
  deadline=time.monotonic()+1800
  while time.monotonic()<deadline:
   if (out/'ROLLBACK').exists():raise RuntimeError('Rollback requested')
   ack=out/'VALIDATED.json'
   if ack.exists():
    a=json.loads(ack.read_text());assert a.get('pdf_valid') and a.get('publish_verified') and a.get('timer_safe')
    for p,data in targets.items():assert p.read_bytes()==data
    assert run('systemctl','is-active','tu1nz-doc.timer').strip()==b'active'
    put(out,'COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'validation':a}).encode());print('DOC_PIPELINE_COMPLETE',flush=True);return
   time.sleep(2)
  raise TimeoutError('No validation acknowledgment')
 except BaseException:
  if changed:restore(out)
  raise
if __name__=='__main__':main()
