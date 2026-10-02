"""V11 authority primitives. No CLI, live installer, service calls or implicit trust."""
import hashlib,json,os,re,stat,unicodedata
from pathlib import Path
BASE='05b127033d734aa4abce10b2e5b7d513b99ed5d2'
TREE='5459b09c4f986ac947dff1466b490a61238cb676'
CHECKOUT='/opt/tu1nz_repos/control'
LIMIT=2_000_000
class Refused(RuntimeError): pass

def sha(b):return hashlib.sha256(b).hexdigest()
def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def acl_free(fd):
 if any('posix_acl' in k for k in os.listxattr(fd)):raise Refused('ACL_NOT_ALLOWED')

def read_bound(path,expected,uid=0,gid=0,mode=0o640,anchor='/',after_open=None):
 """Descriptor walk; fixture anchor is explicit. Live callers must use anchor '/'."""
 path=Path(path);anchor=Path(anchor)
 if not path.is_absolute() or not anchor.is_absolute():raise Refused('ABSOLUTE_PATH_REQUIRED')
 try:parts=path.relative_to(anchor).parts
 except ValueError:raise Refused('OUTSIDE_ANCHOR')
 if not parts or any(x in ('.','..') for x in parts):raise Refused('PATH')
 fd=os.open(anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for part in (*parts[:-1],None):
   s=os.fstat(fd)
   if s.st_uid!=uid or s.st_mode&0o022:raise Refused('WRITABLE_OR_FOREIGN_PARENT')
   acl_free(fd)
   if part is not None:
    nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  try:
   s=os.fstat(f)
   if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=uid or s.st_gid!=gid or stat.S_IMODE(s.st_mode)!=mode or s.st_size>LIMIT:raise Refused('FILE_IDENTITY')
   acl_free(f)
   if after_open:after_open()
   chunks=[];total=0
   while True:
    b=os.read(f,65536)
    if not b:break
    total+=len(b)
    if total>LIMIT:raise Refused('SIZE')
    chunks.append(b)
   b=b''.join(chunks)
   if identity(s)!=identity(os.fstat(f)) or identity(s)!=identity(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)):raise Refused('REPLACED_OR_MODIFIED')
   if sha(b)!=expected:raise Refused('HASH')
   return b
  finally:os.close(f)
 finally:os.close(fd)

def safe_name(name):
 if not name or name.startswith(('/','-')) or '\\' in name or any(unicodedata.category(c).startswith('C') for c in name):raise Refused('NAME')
 if any(x in ('','.','..') or x.startswith('-') for x in name.split('/')):raise Refused('TRAVERSAL_OR_OPTION')
 return name

def filelist(b):
 if not b or len(b)>LIMIT or not b.endswith(b'\n'):raise Refused('LIST_SIZE_OR_TERMINATOR')
 try:lines=b.decode('utf8').split('\n')[:-1]
 except UnicodeError:raise Refused('ENCODING')
 result=[safe_name(x) for x in lines]
 if len(set(result))!=len(result):raise Refused('DUPLICATE')
 return tuple(result)

def checksums(b,allowed):
 """Parse data only. Never call sha256sum -c, shell, eval or open embedded paths."""
 if not b or len(b)>LIMIT or not b.endswith(b'\n'):raise Refused('CHECKSUM_SIZE')
 result={}
 try:lines=b.decode('utf8').split('\n')[:-1]
 except UnicodeError:raise Refused('ENCODING')
 for line in lines:
  m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
  if not m:raise Refused('CHECKSUM_SYNTAX')
  name=safe_name(m[2])
  if name not in allowed or name in result:raise Refused('UNKNOWN_OR_DUPLICATE_PATH')
  result[name]=m[1]
 if set(result)!=set(allowed):raise Refused('MISSING_PATH')
 return result

def compare_measurement(reference,current,allowed):
 # Equality is a comparison of untrusted measurements, NOT proof of disk integrity.
 return checksums(reference,allowed)==checksums(current,allowed)

def deletion_decision(reference,current):
 required=set(filelist(reference));present=set(filelist(current))
 return {'missing':sorted(required-present),'reference_update_permitted':False,'passed':required<=present}

def validate_contract(c,snapshot):
 if c.get('production_basis')!=BASE or c.get('production_tree')!=TREE or c.get('source_of_truth')!='Tausendunde1nz/control':raise Refused('PROVENANCE')
 t=c['target']
 expected={'detached':True,'auto_pull':False,'auto_merge':False,'branch_switch':False,'index_uid':1001,'index_gid':1001,'index_mode':'0600','index_nlink':1,'index_regular':True,'git_reader':'chatops','git_optional_locks':'0','safe_directory':CHECKOUT,'root_git_writes':False,'source_authority':'PINNED_VERSIONED_BYTES_ONLY','untracked_execution_authority':False}
 if t!=expected:raise Refused('TARGET_CONTRACT')
 if snapshot['head']!=BASE or snapshot['tree']!=TREE or snapshot['detached'] is not True or snapshot['tracked_pass'] is not True:raise Refused('TRACKED_BASE')
 before=snapshot['index_before'];after=snapshot['index_after']
 if before!=after or before['uid']!=1001 or before['gid']!=1001 or before['mode']!='0600' or before['nlink']!=1 or before['regular'] is not True:raise Refused('INDEX_IDENTITY')
 if not re.fullmatch('[0-9a-f]{64}',before['sha256']):raise Refused('INDEX_HASH')
 return {'contract':'EXPECTED_CHATOPS_CONTROLLED','tracked_basis':'ACCEPTED','topology':'MIGRATION_REQUIRED' if snapshot['shared_gitdir'] or snapshot['origin']!='Tausendunde1nz/control' else 'ISOLATED','live_ready':False}

def git_read_argv(args):
 # Closed allowlist; root never invokes git directly. No config execution/filter/status.
 allowed=[('rev-parse','HEAD'),('rev-parse','HEAD^{tree}'),('ls-tree','-rz',BASE)]
 if tuple(args) not in allowed:raise Refused('GIT_OPERATION')
 return ['runuser','-u','chatops','--','env','-i','PATH=/usr/bin:/bin','HOME=/nonexistent','GIT_OPTIONAL_LOCKS=0','GIT_CONFIG_NOSYSTEM=1','GIT_CONFIG_GLOBAL=/dev/null','git','-c','safe.directory='+CHECKOUT,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',CHECKOUT,*args]

def privileged_source(path,rule):
 if str(path).startswith(CHECKOUT+'/'):raise Refused('UNVERSIONED_CHECKOUT_AUTHORITY_FORBIDDEN')
 required={'producer','consumer','uid','gid','mode','sha256','versioned_source'}
 if set(rule)!=required or not all(rule[k] for k in ('producer','consumer','versioned_source')) or rule['uid']!=0 or rule['mode'] not in (0o600,0o640,0o644):raise Refused('AUTHORITY_RULE')
 return read_bound(path,rule['sha256'],rule['uid'],rule['gid'],rule['mode'])

def sed_argv(verified_program_fd,source):
 # Caller passes the ALREADY verified still-open descriptor via pass_fds; no pathname reopen.
 if type(verified_program_fd) is not int or verified_program_fd<3:raise Refused('PROGRAM_FD')
 return ['/usr/bin/sed','-f','/proc/self/fd/'+str(verified_program_fd),'--',str(source)]

def sealed_program(data,expected):
 """Immutable anonymous copy for sed -f; caller closes fd and passes only this fd."""
 import fcntl
 if type(data) is not bytes or len(data)>LIMIT or sha(data)!=expected:raise Refused('PROGRAM_HASH')
 fd=os.memfd_create('tu1nz-reviewed-sed',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
 try:
  with os.fdopen(os.dup(fd),'wb') as out:out.write(data);out.flush()
  os.lseek(fd,0,os.SEEK_SET)
  fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
  return fd
 except BaseException:os.close(fd);raise

def verified_program(path,rule):
 data=privileged_source(path,rule)
 return sealed_program(data,rule['sha256'])

def canonicalize_legacy_checksums(data,expected):
 """Offline candidate only: known docs root -> relative names. Never confers trust."""
 if sha(data)!=expected or not data or len(data)>LIMIT or not data.endswith(b'\n'):raise Refused('LEGACY_HASH_OR_SIZE')
 root='/opt/tu1nz_repos/docs/';rows={}
 for line in data.decode('utf8').split('\n')[:-1]:
  m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
  if not m or not m[2].startswith(root):raise Refused('LEGACY_ROOT_OR_FORMAT')
  name=safe_name(m[2][len(root):])
  if name in rows:raise Refused('LEGACY_DUPLICATE')
  rows[name]=m[1]
 result=''.join(rows[n]+'  '+n+'\n' for n in sorted(rows)).encode()
 checksums(result,set(rows))
 return result
