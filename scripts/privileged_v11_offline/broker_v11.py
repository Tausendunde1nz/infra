#!/usr/bin/env -S /usr/bin/python3 -I -B -S
"""V11 diagnostic broker: fixed operations, no lifecycle or command passthrough."""
import collections,fcntl,hashlib,json,os,selectors,signal,stat,subprocess,sys,syslog,time
from pathlib import Path
PROGRAM=Path('/usr/local/sbin/tu1nz-codex-ops-v11')
ROOT=Path('/var/lib/tu1nz-privileged-v11-broker')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/var/empty','PYTHONDONTWRITEBYTECODE':'1'}
UNITS=('tailscaled.service','ssh.service','fail2ban.service','tu1nz_agentmode.service','mychatbuddy-private-alpha.service')
NAMES=('spicymila_bot','telegram_bot_mommyramona','tu1nz_cadvisor')
COMMANDS={
 'status':('/usr/bin/systemctl','show','-p','Id','-p','ActiveState','-p','SubState','-p','Result','-p','MainPID','--',*UNITS),
 'containers':('/usr/bin/docker','--config',str(ROOT/'docker'),'--host','unix:///run/docker.sock','inspect',*NAMES),
 'journal-counts':('/usr/bin/journalctl','--no-pager','--output=json','--since=-1hour','-n','200',*sum((('-u',u) for u in UNITS),())),
}
class Refused(ValueError):pass

def parse(args):
 if len(args)!=1 or args[0] not in COMMANDS:raise Refused('OPERATION_DENIED')
 return args[0]

def trusted(path,directory=False):
 path=Path(path)
 for p in list(reversed(path.parents))+[path]:
  s=p.lstat()
  if s.st_uid!=0 or s.st_mode&0o022 or stat.S_ISLNK(s.st_mode):raise Refused('UNTRUSTED_PATH')
  if any('posix_acl' in x for x in os.listxattr(p,follow_symlinks=False)):raise Refused('ACL')
  if p!=path and not stat.S_ISDIR(s.st_mode):raise Refused('PARENT_TYPE')
 if directory:
  if not stat.S_ISDIR(s.st_mode):raise Refused('DIRECTORY_TYPE')
 elif not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise Refused('FILE_TYPE')
 return s

def read(path,limit=2_000_000):
 trusted(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  b=f.read(limit+1)
 if len(b)>limit:raise Refused('SIZE')
 return b

def run(argv,timeout=20,limit=2_000_000):
 if argv not in COMMANDS.values():raise Refused('COMMAND_DENIED')
 p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,cwd='/',start_new_session=True)
 sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ,'out');sel.register(p.stderr,selectors.EVENT_READ,'err');out=bytearray();count=0;end=time.monotonic()+timeout
 try:
  while sel.get_map():
   if time.monotonic()>=end:raise Refused('TIMEOUT')
   for key,_ in sel.select(min(.1,max(0,end-time.monotonic()))):
    data=os.read(key.fd,65536)
    if not data:sel.unregister(key.fileobj);continue
    count+=len(data)
    if count>limit:raise Refused('SIZE')
    if key.data=='out':out.extend(data)
  if p.wait(timeout=max(.001,end-time.monotonic()))!=0:raise Refused('COMMAND_FAILED')
  return bytes(out)
 finally:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.wait();sel.close();p.stdout.close();p.stderr.close()

def sanitize(op,raw):
 if op=='containers':
  rows=json.loads(raw)
  if len(rows)!=len(NAMES) or {r['Name'].lstrip('/') for r in rows}!=set(NAMES):raise Refused('CONTAINER_SET')
  return [{'name':r['Name'].lstrip('/'),'running':r['State']['Running'] is True,'health':r['State'].get('Health',{}).get('Status') if r['State'].get('Health',{}).get('Status') in ('healthy','unhealthy','starting') else 'none','restart_count':int(r['RestartCount'])} for r in rows]
 if op=='status':
  result=[]
  for block in raw.decode().strip().split('\n\n'):
   row=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
   if row.get('Id') not in UNITS:raise Refused('UNIT_SET')
   result.append({'unit':row['Id'],'active':row.get('ActiveState') if row.get('ActiveState') in ('active','inactive','failed','activating','deactivating','reloading') else 'unknown','pid':int(row.get('MainPID','0'))})
  if {r['unit'] for r in result}!=set(UNITS):raise Refused('UNIT_SET')
  return result
 if op=='journal-counts':
  counts=collections.Counter()
  for line in raw.splitlines():
   row=json.loads(line);unit=row.get('_SYSTEMD_UNIT');priority=row.get('PRIORITY')
   if unit in UNITS and str(priority) in tuple(str(i) for i in range(8)):counts[(unit,str(priority))]+=1
  return [{'unit':u,'priority':p,'count':n} for (u,p),n in sorted(counts.items())]
 raise Refused('OPERATION_DENIED')

def sudoers():
 return ''.join('chatops ALL=(root) NOPASSWD: NOSETENV: '+str(PROGRAM)+' '+op+'\n' for op in COMMANDS)

def main():
 op='denied';rc=77;verified_caller=False;started=time.monotonic_ns()
 try:
  if os.geteuid()!=0 or os.environ.get('SUDO_UID')!='1001' or os.environ.get('SUDO_USER')!='chatops' or Path(__file__)!=PROGRAM or not sys.flags.isolated or not sys.dont_write_bytecode:raise Refused('ENTRY')
  verified_caller=True
  os.environ.clear();os.environ.update(ENV);os.umask(0o077);op=parse(sys.argv[1:]);trusted(ROOT,True)
  manifest=json.loads(read(ROOT/'manifest.json'))
  if hashlib.sha256(read(PROGRAM)).hexdigest()!=manifest['broker_sha256']:raise Refused('SELF_HASH')
  program=COMMANDS[op][0]
  if hashlib.sha256(read(program,64_000_000)).hexdigest()!=manifest['programs'][program]:raise Refused('PROGRAM_HASH')
  trusted(ROOT/'lock');fd=os.open(ROOT/'lock',os.O_RDWR|os.O_NOFOLLOW)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);result=sanitize(op,run(COMMANDS[op]))
   print(json.dumps({'status':'OK','result':result}));rc=0
  finally:os.close(fd)
 except Exception:print('{"status":"DENIED"}')
 finally:
  syslog.openlog('tu1nz-codex-ops-v11');syslog.syslog(syslog.LOG_INFO,json.dumps({'operation':op,'caller':'chatops' if verified_caller else 'unverified','uid':1001 if verified_caller else None,'rc':rc,'elapsed_ns':time.monotonic_ns()-started}));syslog.closelog()
 return rc
if __name__=='__main__':raise SystemExit(main())
