"""Fixed unprivileged current-state observation. No writes and no history search."""
import os,json,hashlib,stat,base64,subprocess,pwd,grp
from pathlib import Path
PATHS=('/etc/sudoers','/etc/sudoers.d','/etc/sudoers.d/90-cloud-init-users','/etc/sudoers.d/99-dokuagent-pandoc','/etc/sudoers.d/chatops-nopass','/etc/sudoers.d/trendwatch-restart','/etc/group','/etc/gshadow','/run/docker.sock','/usr/lib/systemd/system/docker.socket','/usr/lib/systemd/system/docker.service','/etc/docker/daemon.json','/etc/systemd/system/docker.socket.d','/etc/systemd/system/docker.service.d','/etc/cron.d/system_doc_build','/etc/cron.d/system_doc_check','/usr/local/bin/build_system_doc.sh','/usr/local/bin/check_system_doc.sh','/opt/tu1nz_repos/docs','/opt/tu1nz_repos/docs/system_manifest/render_kapitel3.sh','/opt/Tausendunde1nz/_Doku','/var/log/system_doc_check.log','/usr/local/bin/trendwatch_post.sh','/usr/local/bin/trendwatch_fetch.sh','/usr/local/bin/tw_affiliate.sh','/opt/trendwatch','/opt/trendwatch/today_title.txt','/opt/trendwatch/today_live_title.txt','/usr/local/bin/backup_notify.sh','/usr/local/sbin/tu1nz-codex-ops','/usr/local/sbin/tu1nz-mychatbuddy-lifecycle','/etc/systemd/system/mychatbuddy-private-alpha.service','/etc/systemd/system/tu1nz-bot.service','/var/lib/tu1nz-root-only-v9','/usr/local/libexec/tu1nz-root-only-v9','/var/lib/tu1nz-codex-ops')
UNITS=('docker.service','docker.socket','mychatbuddy-private-alpha.service','tu1nz-bot.service','tu1nz_agentmode.service','tu1nz-adult-public-s8-telegram.service','tu1nz-root-only-v9.service','tu1nz-root-only-v9-watchdog.service','tu1nz-root-only-v9-watchdog.timer')+tuple('trendwatch2-'+s+'.'+t for s in ('morning','midday','afternoon','evening') for t in ('service','timer'))
PROPS=('Id','LoadState','ActiveState','SubState','UnitFileState','FragmentPath','DropInPaths','MainPID','NRestarts','NeedDaemonReload','User','Group','SupplementaryGroups','NextElapseUSecRealtime')
def digest(b):return hashlib.sha256(b).hexdigest()
def meta(path):
 p=Path(path)
 try:s=p.lstat()
 except FileNotFoundError:return {'path':path,'absent':True}
 except PermissionError:return {'path':path,'access':'DENIED'}
 r={'path':path,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'type':stat.S_IFMT(s.st_mode),'dev':s.st_dev,'inode':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'chatops_write':os.access(p,os.W_OK),'acl_xattrs':{n:base64.b64encode(os.getxattr(p,n,follow_symlinks=False)).decode() for n in os.listxattr(p,follow_symlinks=False) if 'posix_acl' in n}}
 if stat.S_ISLNK(s.st_mode):r['link']=os.readlink(p)
 if stat.S_ISREG(s.st_mode):
  try:
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   with os.fdopen(fd,'rb') as f:
    b=f.read(32000001)
    if len(b)>32000000:raise ValueError('size bound')
    z=os.fstat(f.fileno())
   if (s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise ValueError('file drift')
   r['sha256']=digest(b)
  except PermissionError:r['content_access']='DENIED'
 return r
def main():
 if os.geteuid()!=1001:raise RuntimeError('chatops only')
 rows=[meta(p) for p in PATHS];units=[]
 for u in UNITS:
  a=['/usr/bin/systemctl','--no-pager']
  for p in PROPS:a+=['-p',p]
  r=subprocess.run(a+['show','--',u],capture_output=True,timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
  props=dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)
  if set(props)-set(PROPS):raise RuntimeError('unexpected property')
  units.append({'unit':u,'properties':props,'rc':r.returncode,'stderr_sha256':digest(r.stderr)})
  for path in [props.get('FragmentPath','')]+props.get('DropInPaths','').split():
   if path and path not in {x['path'] for x in rows}:rows.append(meta(path))
 print(json.dumps({'uid':os.geteuid(),'groups':os.getgroups(),'docker_group':{'gid':grp.getgrnam('docker').gr_gid,'members':grp.getgrnam('docker').gr_mem},'paths':rows,'units':units}))
if __name__=='__main__':main()
