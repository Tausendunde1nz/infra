"""Bounded read-only Control checkout attestation. No source-config Git execution.
Only the root-staged copy has a CLI. All artifacts go beside that protected copy.
No credentials, process arguments, environment values or source contents are exported.
"""
import hashlib,json,os,pathlib,re,stat,subprocess,tempfile,time
ROOT='/opt/tu1nz_repos/control'
COMMIT='b78bb2a753aa815d47a99969668d64960573050b'
TREE='5135053083ceb2e669e5932cf0ff61b3d24dab9d'
OLD='9b383960291da469671c3888cfa4fdcc3c33cf01'
ORIGINS=('git@github.com:Tausendunde1nz/control.git','git@github.com-infra:Tausendunde1nz/control.git','https://github.com/Tausendunde1nz/control.git')
# No reviewed ownership contract currently establishes a privileged-only publisher.
OWNERSHIP_CONTRACT='UNCONFIRMED_MIXED'
LIMIT=64*1024*1024
class Refused(RuntimeError):pass

def sha(data):return hashlib.sha256(data).hexdigest()
def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def metadata(path):
 s=os.lstat(path)
 return dict(uid=s.st_uid,gid=s.st_gid,mode=oct(stat.S_IMODE(s.st_mode)),inode=s.st_ino,device=s.st_dev,nlink=s.st_nlink,size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns,type='file' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else 'other',acl_sha256={k:sha(os.getxattr(path,k,follow_symlinks=False)) for k in os.listxattr(path,follow_symlinks=False) if k.startswith('system.posix_acl_')})
def open_parent(path):
 parts=pathlib.Path(path).parts
 if not pathlib.Path(path).is_absolute() or any(x in ('.','..') for x in parts):raise Refused('PATH')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for x in parts[1:-1]:
   nxt=os.open(x,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  return fd,parts[-1]
 except BaseException:os.close(fd);raise

def read_stable(path,limit=LIMIT):
 parent,name=open_parent(path)
 try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
 finally:os.close(parent)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise Refused('FILE_TYPE_OR_SIZE')
  chunks=[];total=0
  while True:
   b=os.read(fd,min(65536,limit+1-total))
   if not b:break
   total+=len(b)
   if total>limit:raise Refused('SIZE')
   chunks.append(b)
  if identity(a)!=identity(os.fstat(fd)) or identity(a)!=identity(os.lstat(path)):raise Refused('READ_RACE')
  return b''.join(chunks)
 finally:os.close(fd)

def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())

def publish(directory,name,obj):
 data=json.dumps(obj,sort_keys=True,ensure_ascii=True).encode()+b'\n';tmp=directory/('.'+name+'-'+os.urandom(8).hex())
 write_new(tmp,data);os.link(tmp,directory/name,follow_symlinks=False);tmp.unlink()
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return sha(data)

class SafeGit:
 def __init__(self,source,scratch,index,head):
  self.source=pathlib.Path(source);self.gitdir=scratch/'git';self.gitdir.mkdir(mode=0o700)
  (self.gitdir/'refs').mkdir(mode=0o700);(self.gitdir/'objects').mkdir(mode=0o700)
  write_new(self.gitdir/'HEAD',head);write_new(self.gitdir/'index',index)
  write_new(self.gitdir/'config',b'[core]\nrepositoryformatversion = 0\nbare = false\n')
  # Never read local .git/config as configuration. Object payloads are hash checked.
  self.env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','XDG_CONFIG_HOME':'/nonexistent','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_NO_REPLACE_OBJECTS':'1','GIT_TERMINAL_PROMPT':'0','GIT_OBJECT_DIRECTORY':str(self.source/'.git/objects')}
 def run(self,args,expected=(0,)):
  if not args or args[0] not in ('cat-file','ls-files','merge-base','config'):raise Refused('GIT_VERB')
  cmd=['/usr/bin/git','--no-replace-objects','--git-dir='+str(self.gitdir),'--work-tree='+str(self.source),'-c','core.fsmonitor=false','-c','core.untrackedCache=false','-c','core.hooksPath=/dev/null','-c','core.attributesFile=/dev/null','-c','diff.external=','-c','core.pager=cat','-c','maintenance.auto=false','-c','gc.auto=0',*args]
  # A private bounded spool avoids exporting diagnostic/config contents.
  with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
   p=subprocess.run(cmd,cwd='/',env=self.env,stdout=out,stderr=err,timeout=30)
   if p.returncode not in expected:raise Refused('GIT_RETURN_CODE')
   if out.tell()>LIMIT or err.tell()>1024*1024:raise Refused('GIT_OUTPUT_SIZE')
   if err.tell():raise Refused('GIT_STDERR')
   out.seek(0);return p.returncode,out.read()
 def object(self,kind,oid):
  if kind not in ('commit','tree') or not re.fullmatch('[0-9a-f]{40}',oid):raise Refused('OBJECT')
  data=self.run(['cat-file',kind,oid])[1]
  if hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid:raise Refused('OBJECT_HASH')
  return data
 def tree(self,oid,prefix=b'',depth=0):
  if depth>32:raise Refused('TREE_DEPTH')
  data=self.object('tree',oid);result={}
  while data:
   nul=data.index(b'\0');mode,name=data[:nul].split(b' ',1);child=data[nul+1:nul+21].hex();data=data[nul+21:]
   if name in (b'.',b'..',b'.git') or b'/' in name or not name:raise Refused('TREE_PATH')
   path=prefix+name
   if mode==b'40000':result.update(self.tree(child,path+b'/',depth+1))
   elif mode in (b'100644',b'100755',b'120000'):result[path]=(mode.decode(),child)
   else:raise Refused('UNSUPPORTED_TREE_MODE')
   if len(result)>100000:raise Refused('TREE_SIZE')
  return result

def config_summary(git,path):
 pairs=git.run(['config','--no-includes','--file',str(path),'--null','--list'])[1].split(b'\0');keys=[];origin=None;danger=[]
 for pair in filter(None,pairs):
  k,_,v=pair.partition(b'\n');key=k.decode('ascii','strict').lower();keys.append(key)
  if key=='remote.origin.url':
   if origin is not None:raise Refused('DUPLICATE_ORIGIN')
   origin=v.decode('utf-8','strict')
  if key.startswith(('include.','includeif.','filter.','diff.','extensions.')) or key in ('core.hookspath','core.fsmonitor','core.attributesfile','core.worktree','core.sshcommand'):danger.append({'key':key if re.fullmatch('[a-z0-9.-]+',key) else 'REDACTED_KEY','value_sha256':sha(v)})
 return {'origin':origin if origin in ORIGINS or origin=='git@github.com-infra:Tausendunde1nz/infra.git' else 'REDACTED_UNEXPECTED_ORIGIN','origin_sha256':sha((origin or '').encode()),'origin_matches_reference_repository':origin in ORIGINS,'external_features':danger,'source_config_executed':False}

def walk_error(error):raise Refused("DIRECTORY_ENUMERATION")

def inventory(root):
 result={};count=0
 for base,dirs,files in os.walk(root,followlinks=False,onerror=walk_error):
  for name in sorted(dirs+files):
   p=pathlib.Path(base)/name;rel=str(p.relative_to(root));m=metadata(p);result[rel]=m;count+=1
   if m['type'] in ('symlink','other'):raise Refused('GIT_METADATA_LINK_OR_TYPE')
   if count>100000:raise Refused('GIT_METADATA_SIZE')
 return result

def process_scan(root,proc=pathlib.Path('/proc')):
 rows=[];incomplete=False;prefix=str(root)+'/'
 for p in proc.iterdir():
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  try:
   cwd=os.readlink(p/'cwd');fds=[]
   for fd in (p/'fd').iterdir():
    try:
     target=os.readlink(fd);match=re.search(r'^flags:\s+([0-7]+)$',(p/'fdinfo'/fd.name).read_text(),re.M)
     if match and int(match[1],8)&3 in (1,2) and (target==str(root) or target.startswith(prefix)):fds.append({'fd':int(fd.name),'path':target})
    except FileNotFoundError:continue
   if cwd==str(root) or cwd.startswith(prefix) or fds:rows.append({'pid':int(p.name),'cwd_in_checkout':cwd==str(root) or cwd.startswith(prefix),'writable_fds':fds})
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:incomplete=True
 return {'processes':rows,'incomplete':incomplete}

def classify(proof):
 if proof['writers'] or proof['locks']:return 'ACTIVE_WRITER_OR_TRANSACTION'
 if proof['drift']:return 'LOCAL_CHECKOUT_DRIFT'
 if proof['complete'] and proof['root_controlled'] and proof['contract_confirmed']:return 'TRUSTED_CLEAN_ROOT_CONTROLLED_CHECKOUT'
 return 'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN'

def worktree_metadata(root):
 result={}
 for base,dirs,files in os.walk(root,followlinks=False,onerror=walk_error):
  if pathlib.Path(base)==root:dirs[:]=[x for x in dirs if x!='.git']
  for name in dirs+files:
   p=pathlib.Path(base)/name;result[str(p.relative_to(root))]=metadata(p)
   if len(result)>100000:raise Refused('WORKTREE_SIZE')
 return result

def attest(root,scratch,commit=COMMIT,tree=TREE,old=OLD,processes=process_scan):
 root=pathlib.Path(root)
 if str(root.resolve())!=str(root):raise Refused('CANONICAL_PATH')
 start=time.monotonic_ns();meta_before=inventory(root/'.git')
 for x in ('objects/info/alternates','objects/info/http-alternates','info/grafts','commondir','shallow'):
  if x in meta_before:raise Refused('UNSUPPORTED_OBJECT_INDIRECTION')
 before=processes(root);locks=[x for x in meta_before if x.endswith('.lock')]
 if before['processes'] or locks:return {'schema':1,'status':'ACTIVE_WRITER_OR_TRANSACTION','canonical_path':str(root),'writers':before,'locks':locks,'local_commit_verified':False}
 work_before=worktree_metadata(root)
 index=read_stable(root/'.git/index');head=read_stable(root/'.git/HEAD',8192);cfg=read_stable(root/'.git/config',1024*1024)
 git=SafeGit(root,scratch,index,head);write_new(scratch/'source-config',cfg);conf=config_summary(git,scratch/'source-config')
 payload=git.object('commit',commit);actual_tree=payload.split(b'\n',1)[0].decode().removeprefix('tree ')
 if actual_tree!=tree:raise Refused('TRUSTED_TREE_MISMATCH')
 ancestry=git.run(['merge-base','--is-ancestor',old,commit],expected=(0,1))[0]==0
 expected=git.tree(tree);raw=git.run(['ls-files','--stage','-z'])[1];actual={};conflicts=[]
 for line in filter(None,raw.split(b'\0')):
  info,path=line.split(b'\t',1);mode,oid,stage=info.split()
  if stage!=b'0' or path in actual:conflicts.append(path.decode('utf-8','backslashreplace'))
  actual[path]=(mode.decode(),oid.decode())
 drift=[]
 if head.strip()!=commit.encode():drift.append({'path':'.git/HEAD','reason':'NOT_EXPECTED_DETACHED_HEAD'})
 if not ancestry:drift.append({'path':'.git/objects','reason':'ANCESTRY_MISMATCH'})
 if actual!=expected or conflicts:drift.append({'path':'.git/index','reason':'INDEX_TREE_MISMATCH','paths':[p.decode('utf-8','backslashreplace') for p in sorted(set(actual)|set(expected)) if actual.get(p)!=expected.get(p)],'conflicts':conflicts})
 worktree=[]
 for rel,(mode,oid) in sorted(expected.items()):
  path=root/os.fsdecode(rel)
  try:
   a=os.lstat(path)
   if mode=='120000':
    if not stat.S_ISLNK(a.st_mode):raise Refused('TYPE')
    parent,name=open_parent(path)
    try:data=os.fsencode(os.readlink(name,dir_fd=parent))
    finally:os.close(parent)
    if identity(a)!=identity(os.lstat(path)):raise Refused('RACE')
   else:
    data=read_stable(path)
    if bool(a.st_mode&stat.S_IXUSR)!=(mode=='100755'):raise Refused('EXECUTABLE_MODE')
   digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
   if digest!=oid:raise Refused('CONTENT')
   worktree.append([os.fsdecode(rel),sha(data),mode])
  except (OSError,Refused) as e:drift.append({'path':os.fsdecode(rel),'reason':type(e).__name__})
 untracked=[]
 for base,dirs,files in os.walk(root,followlinks=False,onerror=walk_error):
  if pathlib.Path(base)==root:dirs[:]=[x for x in dirs if x!='.git']
  for name in files+[x for x in dirs if (pathlib.Path(base)/x).is_symlink()]:
   rel=os.fsencode(str((pathlib.Path(base)/name).relative_to(root)))
   if rel not in expected:untracked.append(os.fsdecode(rel))
   if len(untracked)>100000:raise Refused('UNTRACKED_LIMIT')
 if untracked:drift.append({'path':'.','reason':'UNTRACKED_INCLUDING_IGNORED','paths':sorted(untracked)})
 after=processes(root);meta_after=inventory(root/'.git')
 if work_before!=worktree_metadata(root):drift.append({'path':'.','reason':'CONCURRENT_WORKTREE_CHANGE'})
 if meta_before!=meta_after or read_stable(root/'.git/index')!=index or read_stable(root/'.git/HEAD')!=head or read_stable(root/'.git/config')!=cfg:drift.append({'path':'.git','reason':'CONCURRENT_METADATA_CHANGE'})
 chain=[root,*root.parents,root/'.git'];chainmeta={str(p):metadata(p) for p in chain}
 protected=all(v['uid']==0 and not int(v['mode'],8)&0o022 and not v['acl_sha256'] for v in chainmeta.values()) and all(v['uid']==0 and not int(v['mode'],8)&0o022 and not v['acl_sha256'] for v in meta_after.values())
 writers=before['processes']+after['processes'];proof={'writers':writers,'locks':locks,'drift':drift,'complete':not(before['incomplete'] or after['incomplete']),'root_controlled':protected,'contract_confirmed':OWNERSHIP_CONTRACT=='ROOT_CONTROLLED_DOCUMENTED'}
 origin_ref=None
 if 'refs/remotes/origin/main' in meta_after:origin_ref=read_stable(root/'.git/refs/remotes/origin/main',4096).decode().strip()
 elif 'packed-refs' in meta_after:
  for line in read_stable(root/'.git/packed-refs').splitlines():
   if line.endswith(b' refs/remotes/origin/main'):origin_ref=line.split()[0].decode()
 if origin_ref is not None and not re.fullmatch('[a-f0-9]{40}',origin_ref):raise Refused('REF_FORMAT')
 return {'schema':1,'status':classify(proof),'canonical_path':str(root),'expected_commit':commit,'expected_tree':tree,'commit_type':'commit','expected_commit_content_verified':True,'ancestor':old,'ancestor_verified':ancestry,'detached':not head.startswith(b'ref: '),'head':head.decode().strip() if re.fullmatch(rb'[a-f0-9]{40}\n?',head) else 'SYMBOLIC_OR_UNEXPECTED','origin_main':origin_ref,'remote':conf,'index_sha256':sha(index),'index_metadata':metadata(root/'.git/index'),'git_metadata':meta_after,'ownership_chain':chainmeta,'ownership_contract':OWNERSHIP_CONTRACT,'worktree_manifest_sha256':sha(json.dumps(worktree,sort_keys=True).encode()),'tracked_files_checked':len(worktree),'untracked':untracked,'proof':proof,'start_ns':start,'end_ns':time.monotonic_ns(),'boot_id':read_stable('/proc/sys/kernel/random/boot_id',128).decode().strip(),'freshness':'POINT_IN_TIME_NOT_A_LOCK_OR_SIGNATURE'}

def main():
 if os.geteuid()!=0:raise Refused('ROOT_REQUIRED')
 stage=pathlib.Path(__file__).parent;out=stage.parent
 if not re.fullmatch(r'tu1nz-v11-checkout-attestation-[a-z0-9_]+',out.name) or out.parent!=pathlib.Path('/var/lib') or stage.name!='staging':raise Refused('OUTPUT_PATH')
 for p in (out,stage):
  m=metadata(p)
  if m['uid']!=0 or int(m['mode'],8)&0o022 or m['acl_sha256']:raise Refused('OUTPUT_OWNERSHIP')
 os.umask(0o077);scratch=out/'private';scratch.mkdir(mode=0o700)
 try:result=attest(ROOT,scratch)
 except BaseException as e:result={'schema':1,'status':'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN','error_class':type(e).__name__,'local_commit_verified':False}
 digest=publish(scratch,'report.json',result)
 export=out/'redacted';export.mkdir(mode=0o750);os.chown(export,0,1001);os.chmod(export,0o750)
 publish(export,'report.json',result);os.chown(export/'report.json',0,1001);os.chmod(export/'report.json',0o640)
 publish(scratch,'manifest.json',{'report_sha256':digest,'collector_sha256':sha(read_stable(__file__)),'status':result['status'],'live_mutations':False})
 print(json.dumps({'status':result['status'],'report':str(export/'report.json'),'sha256':digest}),flush=True)
 return 0 if result['status']=='TRUSTED_CLEAN_ROOT_CONTROLLED_CHECKOUT' else 2
if __name__=='__main__':
 try:raise SystemExit(main())
 except Refused as e:print('ATTESTATION_REFUSED:'+type(e).__name__);raise SystemExit(3)
