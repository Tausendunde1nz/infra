"""Metadata-only classification helpers. Never executes or imports an inspected file."""
import hashlib,os,pathlib,re,stat,struct
LIMIT=8*1024*1024
class Refused(RuntimeError):pass

def acl(raw):
 if len(raw)<4 or (len(raw)-4)%8 or struct.unpack('<I',raw[:4])[0]!=2:raise Refused('ACL_FORMAT')
 names={1:'user_obj',2:'user',4:'group_obj',8:'group',16:'mask',32:'other'};rows=[]
 for off in range(4,len(raw),8):
  tag,perm,ident=struct.unpack('<HHI',raw[off:off+8])
  if tag not in names or perm>7:raise Refused('ACL_ENTRY')
  rows.append({'tag':names[tag],'permissions':perm,'id':None if ident==0xffffffff else ident})
 mask=next((x['permissions'] for x in rows if x['tag']=='mask'),7)
 for x in rows:x['effective_permissions']=x['permissions']&mask if x['tag'] in ('user','group','group_obj') else x['permissions']
 return rows

def categories(name,mode):
 if stat.S_ISLNK(mode):return ['symlink']
 if '/__pycache__/' in name and name.endswith('.pyc'):return ['cache']
 if name.endswith(('.pid','.lock')) or name in ('last_sync.ok','monitor_last.txt'):return ['runtime_status']
 if name.endswith(('.tar.gz','.bak','.before','.paused')) or '.bak_' in name:return ['backup','operator_state']
 if name.endswith(('.service','.timer','.socket','.path','.conf','.py','.sh')) or bool(mode&0o111):return ['possible_source_or_configuration']
 if name.startswith(('analysis/','rebaseline_2026/')):return ['operator_state']
 if any(x in name for x in ('checksum','integrity','filelist')):return ['runtime_status','operator_state']
 return ['operator_state']

def inventory_one(root,rel):
 parts=pathlib.PurePosixPath(rel).parts
 if not parts or rel.startswith('/') or any(x in ('.','..','.git') for x in parts):raise Refused('PATH_SCOPE')
 root=pathlib.Path(root);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parents=[]
  for part in parts[:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
   st=os.fstat(fd);parents.append({'component':part,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))})
  st=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False);kind='regular' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'special'
  r={'path':rel,'type':kind,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),'size':st.st_size,'inode':st.st_ino,'nlink':st.st_nlink,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'parents':parents,'categories':categories(rel,st.st_mode),'sha256':None,'hash_reason':None,'acls':{},'relevant_xattrs':[]}
  p=root/rel
  try:
   for key in os.listxattr(p,follow_symlinks=False):
    if key.startswith('system.posix_acl_'):r['acls'][key]=acl(os.getxattr(p,key,follow_symlinks=False))
    elif key.startswith(('security.','trusted.')):r['relevant_xattrs'].append(key)
  except OSError as e:r['xattr_error']=type(e).__name__
  if kind=='symlink':r['link_target']=re.sub(r'(://)[^/@]+@',r'\1[REDACTED]@',os.readlink(parts[-1],dir_fd=fd));r['hash_reason']='SYMLINK_NOT_FOLLOWED'
  elif kind!='regular':r['hash_reason']='NOT_REGULAR'
  elif st.st_nlink!=1:r['hash_reason']='HARDLINK_NOT_OPENED'
  elif st.st_size>LIMIT:r['hash_reason']='SIZE_LIMIT'
  elif 'runtime_status' in r['categories']:r['hash_reason']='POTENTIALLY_ACTIVE_RUNTIME_NOT_OPENED'
  else:
   f=None
   try:
    f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);a=os.fstat(f)
    if not stat.S_ISREG(a.st_mode) or (a.st_dev,a.st_ino)!=(st.st_dev,st.st_ino):raise Refused('OPEN_RACE')
    h=hashlib.sha256();total=0
    while True:
     b=os.read(f,65536)
     if not b:break
     total+=len(b)
     if total>LIMIT:raise Refused('READ_LIMIT')
     h.update(b)
    z=os.fstat(f);end=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
    def sig(x):return(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if sig(a)!=sig(z) or sig(a)!=sig(end):raise Refused('CONTENT_RACE')
    r['sha256']=h.hexdigest();r['hash_reason']='STABLE_REGULAR_BYTES_ONLY'
   except (OSError,Refused) as e:r['hash_reason']=type(e).__name__
   finally:
    if f is not None:os.close(f)
  return r
 finally:os.close(fd)

def dimensions(tracked,entries,contract,writers=False):
 if tracked not in ('PASS','FAIL','UNPROVEN') or contract not in ('EXPECTED_ROOT_CONTROLLED','EXPECTED_CHATOPS_CONTROLLED','CONTRADICTORY','UNPROVEN'):raise Refused('STATUS')
 kinds={x['impact'] for x in entries}
 if not kinds<= {'BENIGN','EXECUTION_RELEVANT','SECURITY_RELEVANT','UNKNOWN'}:raise Refused('IMPACT')
 impact=next((v for v in ('SECURITY_RELEVANT','EXECUTION_RELEVANT','UNKNOWN','BENIGN') if v in kinds),'BENIGN')
 if writers:overall='ACTIVE_WRITER_OR_TRANSACTION'
 elif tracked=='FAIL':overall='LOCAL_CHECKOUT_DRIFT'
 elif tracked!='PASS':overall='CHECKOUT_CONTRACT_UNPROVEN'
 elif any(x.get('active_shadow_risk') is True for x in entries):overall='TRUSTED_TRACKED_BUT_EXECUTION_SHADOW_RISK'
 elif tracked!='PASS' or contract in ('UNPROVEN','CONTRADICTORY') or 'UNKNOWN' in kinds:overall='CHECKOUT_CONTRACT_UNPROVEN'
 elif kinds=={'BENIGN'} or not kinds:overall='TRUSTED_CLEAN_TRACKED_WITH_BENIGN_UNTRACKED_STATE'
 elif all(x.get('controlled') is True for x in entries if x['impact']!='BENIGN'):overall='TRUSTED_TRACKED_WITH_CONTROLLED_OPERATIONAL_STATE'
 else:overall='CHECKOUT_CONTRACT_UNPROVEN'
 return {'TRACKED_INTEGRITY':tracked,'UNTRACKED_IMPACT':impact,'CHECKOUT_CONTRACT':contract,'overall':overall}
