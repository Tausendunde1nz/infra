"""E1 fixed personal Mac sudo entry; first actual file restore, no network.

The historical HOLD is preserved. Only a fully bound new DB PASS permits entry.
No arbitrary path/code option, production restore, retry or generic root helper.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

INPUT=Path('/Users/daniel/Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101/execution/db-completion')
SOURCE=Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')
OUTPUT=Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/pre-stop-protection/public-rights-20261014-1')


class Denied(RuntimeError):pass
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,limit):
    need(path.resolve(strict=True)==path,'E1_ROOT_INPUT_CANONICAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600 and
             s.st_nlink==1 and 0<=s.st_size<=limit,'E1_ROOT_INPUT_PROFILE')
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==s.st_size and all(tuple(getattr(a,k) for k in fields)==tuple(getattr(s,k) for k in fields)
             for a in (os.fstat(fd),path.lstat())),'E1_ROOT_INPUT_CHANGED')
        return raw
    finally:os.close(fd)


def write_receipt(parent,name,raw):
    need(name in ('FILE_RESTORE_RESULT.json','PROTECTION_COMPLETION.json'),'E1_ROOT_OUTPUT_SET')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.fchown(fd,501,20);os.fsync(fd)
    finally:os.close(fd)
    os.fsync(parent);need(read(OUTPUT/name,len(raw)+1)==raw,'E1_ROOT_RESULT_READBACK')


def empty_restore_entries(parent_fd,created_fd,f):
    identity=lambda s:(s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode))
    s=os.fstat(created_fd);named=os.stat('privileged-restore',dir_fd=parent_fd,follow_symlinks=False)
    need(identity(s)==identity(named) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and
         os.listdir(created_fd)==['file-restore'],'E1_ROOT_ENTRY_CHANGED')
    f.NativeMac().plain(created_fd)
    fd=os.open('file-restore',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=created_fd)
    try:
        s=os.fstat(fd);named=os.stat('file-restore',dir_fd=created_fd,follow_symlinks=False)
        need(identity(s)==identity(named) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and
             os.listdir(fd)==[],'E1_ROOT_RESTORE_NOT_EMPTY');f.NativeMac().plain(fd)
    finally:os.close(fd)
    return {'own_test_copies_removed':True,'two_empty_root_owned_entry_directories_retained':True}


def main():
    need(sys.platform=='darwin' and os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')=='501' and
         os.environ.get('SUDO_GID')=='20' and len(sys.argv)==1,'E1_PERSONAL_MAC_ROOT_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope_raw=read(INPUT/'SCOPE.json',512*1024);scope=json.loads(scope_raw)
    review=json.loads(read(INPUT/'INDEPENDENT_REVIEW.json',65536))
    need(review.get('verdict')=='PASS' and review.get('independent_of_implementer') is True and
         review.get('scope_sha256')==sha(scope_raw) and review.get('unresolved_findings')==[],'E1_ROOT_REVIEW_REQUIRED')
    name='tu1nz_mainserver_db_completion.py';raw=read(INPUT/'source'/name,256*1024)
    need(sha(raw)==scope['source_sha256'][name] and (SOURCE/name).read_bytes()==raw,'E1_ROOT_MODULE_CHANGED')
    c=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,None));exec(compile(raw,name,'exec'),c.__dict__)
    checked,scope_sha,review_sha,source,b=c.validate_inputs()
    need(checked==scope and c.OUTPUT==OUTPUT and Path(__file__).resolve(strict=True)==INPUT/'source'/'tu1nz_mainserver_db_file_restore.py' and
         Path(__file__).read_bytes()==source['tu1nz_mainserver_db_file_restore.py'],'E1_ROOT_SELF_BINDING')
    r=c.load('tu1nz_mainserver_restore.py',source['tu1nz_mainserver_restore.py'])
    f=c.load('tu1nz_mainserver_file_restore.py',source['tu1nz_mainserver_file_restore.py'])
    entry=c.load('tu1nz_mainserver_file_restore_entry.py',source['tu1nz_mainserver_file_restore_entry.py'])
    manifest,blobs,paths,originals=c.prior_files(scope,b,f,phase='root')
    db_raw,db=c.checked_db_receipt(scope,scope_sha,review_sha,r)
    parent_identity=c.directory(OUTPUT)
    fd=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    need(tuple(getattr(os.fstat(fd),k) for k in ('st_dev','st_ino','st_uid','st_mode'))==parent_identity,'E1_ROOT_PARENT_CHANGED')
    created=None;receipt={'schema':'TU1NZ_E1_REAL_FILE_RESTORE_V1','status':'HOLD','scope_sha256':scope_sha,
        'review_sha256':review_sha,'db_result_sha256':sha(db_raw),'original_hold_sha256':c.OLD_RESULT,
        'original_remote_closed_ACK_received':False,'real_uid':os.getuid(),'effective_uid':os.geteuid(),
        'source_sha256':scope['source_sha256']['tu1nz_mainserver_file_restore.py'],
        'host_contacted':False,'production_restore':False,'started_unix':time.time()}
    try:
        os.mkdir('privileged-restore',0o700,dir_fd=fd)
        created=os.open('privileged-restore',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        entry.bind_created_parent(fd,created)
        receipt['proof']=f.restore_private_files(created,manifest,blobs,paths,deadline=time.monotonic()+120)
        receipt['cleanup']=empty_restore_entries(fd,created,f)
        for name,raw in originals.items():need(read(OUTPUT/name,1024*1024)==raw,'E1_ROOT_ORIGINAL_CHANGED')
        need(read(OUTPUT/'DB_COMPLETION_RESULT.json',512*1024)==db_raw,'E1_ROOT_DB_RESULT_CHANGED')
        receipt['status']='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS'
    except BaseException as error:
        receipt['failure']=str(error) if isinstance(error,(Denied,c.Denied,f.Denied)) else type(error).__name__
    finally:
        receipt['finished_unix']=time.time()
        raw=c.canonical(receipt);write_receipt(fd,'FILE_RESTORE_RESULT.json',raw)
        try:
            if receipt['status']=='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS':
                c.prior_files(scope,b,f,phase='final');empty_restore_entries(fd,created,f)
                verified_db,_=c.checked_db_receipt(scope,scope_sha,review_sha,r)
                need(verified_db==db_raw and sha(read(INPUT/'SCOPE.json',512*1024))==scope_sha and
                     sha(read(INPUT/'INDEPENDENT_REVIEW.json',65536))==review_sha,'E1_FINAL_BINDING_CHANGED')
                need(c.directory(OUTPUT)==parent_identity,'E1_ROOT_PARENT_CHANGED')
                completion={'schema':'TU1NZ_E1_PROTECTION_COMPLETION_V1','status':'PASS_REAL_DB_AND_FILE_RESTORES',
                    'scope_sha256':scope_sha,'review_sha256':review_sha,'db_result_sha256':sha(db_raw),'file_result_sha256':sha(raw),
                    'original_attempt_sha256':c.OLD_ATTEMPT,'original_hold_sha256':c.OLD_RESULT,
                    'original_attempt_remains_FAILED_HOLD':True,'original_remote_closed_ACK_received':False,
                    'original_remote_cleanup_observed':False,'original_reader_replayed':False,'file_objects':102,'lighting_objects':88,
                    'file_manifest_sha256':scope['original_sha256']['files.json'],'actual_local_cleanup':receipt['cleanup'],
                    'not_global_atomic_or_writer_fenced':True,'not_production_restore_permission':True,
                    'not_V1_V6_or_maintenance_acceptance':True,'finished_unix':time.time()}
                write_receipt(fd,'PROTECTION_COMPLETION.json',c.canonical(completion))
        finally:
            if created is not None:os.close(created)
            os.close(fd)
    print('E1 Dateirestore:',receipt['status'],'— unveränderter Attributvergleich und private Cleanupprüfung.')
    return 0 if receipt['status']=='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('E1 lokaler Restore abgebrochen:',str(error) if isinstance(error,Denied) else type(error).__name__)
        raise SystemExit(1)
