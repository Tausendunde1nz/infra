"""First personal privileged restore admitted only by the separate S7 PASS.

Original and E1 HOLD remain immutable. Same closed actual file restoration and
attribute comparison; all new output is in the approved supplement directory.
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

INPUT=Path('/Users/daniel/Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101/execution/s7-supplement-20261106')
SOURCE=Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')
OUTPUT=Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/pre-stop-protection/public-rights-20261014-1/s7-supplement-20261106')


class Denied(RuntimeError):pass
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,limit):
    need(path.resolve(strict=True)==path,'S7_ROOT_INPUT_CANONICAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600 and
             s.st_nlink==1 and 0<=s.st_size<=limit,'S7_ROOT_INPUT_PROFILE')
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==s.st_size and all(tuple(getattr(v,k) for k in fields)==tuple(getattr(s,k) for k in fields)
             for v in (os.fstat(fd),path.lstat())),'S7_ROOT_INPUT_CHANGED')
        return raw
    finally:os.close(fd)


def write_receipt(parent,name,raw):
    need(name in ('FILE_RESTORE_RESULT.json','PROTECTION_COMPLETION.json'),'S7_ROOT_OUTPUT_SET')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.fchown(fd,501,20);os.fsync(fd)
    finally:os.close(fd)
    os.fsync(parent);need(read(OUTPUT/name,len(raw)+1)==raw,'S7_ROOT_RESULT_READBACK')


def main():
    need(sys.platform=='darwin' and os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')=='501' and
         os.environ.get('SUDO_GID')=='20' and len(sys.argv)==1 and sys.stdin.isatty(),'S7_PERSONAL_MAC_ROOT_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope_raw=read(INPUT/'SCOPE.json',512*1024);scope=json.loads(scope_raw)
    review=json.loads(read(INPUT/'INDEPENDENT_REVIEW.json',65536))
    need(review.get('verdict')=='PASS' and review.get('independent_of_implementer') is True and
         review.get('scope_sha256')==sha(scope_raw) and review.get('unresolved_findings')==[],'S7_ROOT_REVIEW_REQUIRED')
    name='tu1nz_mainserver_s7_supplement.py';raw=read(INPUT/'source'/name,256*1024)
    need(sha(raw)==scope['source_sha256'][name] and (SOURCE/name).read_bytes()==raw,'S7_ROOT_MODULE_CHANGED')
    s=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,None));exec(compile(raw,name,'exec'),s.__dict__)
    checked,scope_sha,review_sha,source,c,b,old=s.validate_inputs()
    need(checked==scope and s.OUTPUT==OUTPUT and Path(__file__).resolve(strict=True)==INPUT/'source'/'tu1nz_mainserver_s7_file_restore.py' and
         Path(__file__).read_bytes()==source['tu1nz_mainserver_s7_file_restore.py'],'S7_ROOT_SELF_BINDING')
    r=s.load('tu1nz_mainserver_restore.py',source['tu1nz_mainserver_restore.py'])
    f=s.load('tu1nz_mainserver_file_restore.py',source['tu1nz_mainserver_file_restore.py'])
    entry=s.load('tu1nz_mainserver_file_restore_entry.py',source['tu1nz_mainserver_file_restore_entry.py'])
    old_entry=s.load('tu1nz_mainserver_db_file_restore.py',source['tu1nz_mainserver_db_file_restore.py'])
    manifest,blobs,paths,originals=s.prior_files(scope,c,b,f,old,supplement_exists=True)
    db_raw,db=s.checked_db_receipt(scope,scope_sha,review_sha,r,old)
    parent_identity=s.directory(OUTPUT)
    fd=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    need(s.identity(os.fstat(fd))==parent_identity,'S7_ROOT_PARENT_CHANGED')
    created=None;receipt={'schema':'TU1NZ_S7_REAL_FILE_RESTORE_V1','status':'HOLD','scope_sha256':scope_sha,
        'review_sha256':review_sha,'db_result_sha256':sha(db_raw),'e1_hold_sha256':s.E1_RESULT,
        'original_hold_sha256':c.OLD_RESULT,'original_remote_closed_ACK_received':False,
        'real_uid':os.getuid(),'effective_uid':os.geteuid(),'source_sha256':scope['source_sha256']['tu1nz_mainserver_file_restore.py'],
        'host_contacted':False,'production_restore':False,'started_unix':time.time()}
    try:
        os.mkdir('privileged-restore',0o700,dir_fd=fd)
        created=os.open('privileged-restore',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        entry.bind_created_parent(fd,created)
        receipt['proof']=f.restore_private_files(created,manifest,blobs,paths,deadline=time.monotonic()+120)
        receipt['cleanup']=old_entry.empty_restore_entries(fd,created,f)
        for name,data in originals.items():need(read(s.PARENT/name,1024*1024)==data,'S7_ROOT_ORIGINAL_CHANGED')
        need(read(OUTPUT/'RESULT.json',512*1024)==db_raw,'S7_ROOT_DB_RESULT_CHANGED')
        receipt['status']='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS'
    except BaseException as error:
        receipt['failure']=str(error) if isinstance(error,(Denied,s.Denied,c.Denied,f.Denied,entry.Denied,old_entry.Denied)) else type(error).__name__
    finally:
        receipt['finished_unix']=time.time();raw=s.canonical(receipt);write_receipt(fd,'FILE_RESTORE_RESULT.json',raw)
        try:
            if receipt['status']=='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS':
                s.prior_files(scope,c,b,f,old,supplement_exists=True);old_entry.empty_restore_entries(fd,created,f)
                verified_db,_=s.checked_db_receipt(scope,scope_sha,review_sha,r,old,files_done=True)
                need(verified_db==db_raw and sha(read(INPUT/'SCOPE.json',512*1024))==scope_sha and
                     sha(read(INPUT/'INDEPENDENT_REVIEW.json',65536))==review_sha,'S7_FINAL_BINDING_CHANGED')
                need(s.directory(OUTPUT)==parent_identity,'S7_ROOT_PARENT_CHANGED')
                completion={'schema':'TU1NZ_S7_PROTECTION_COMPLETION_V1','status':'PASS_REAL_DB_AND_FILE_RESTORES',
                    'scope_sha256':scope_sha,'review_sha256':review_sha,'db_result_sha256':sha(db_raw),'file_result_sha256':sha(raw),
                    'e1_attempt_sha256':s.E1_ATTEMPT,'e1_hold_sha256':s.E1_RESULT,'original_attempt_sha256':c.OLD_ATTEMPT,
                    'original_hold_sha256':c.OLD_RESULT,'original_and_E1_remain_HOLD':True,'original_remote_closed_ACK_received':False,
                    'original_reader_replayed':False,'file_objects':102,'lighting_objects':88,
                    'file_manifest_sha256':old['original_sha256']['files.json'],'actual_local_cleanup':receipt['cleanup'],
                    'not_global_atomic_or_writer_fenced':True,'not_production_restore_permission':True,
                    'not_V1_V6_or_maintenance_acceptance':True,'maintenance_time_gap_assessment_required':True,
                    'db_snapshot_started_unix':db['snapshot']['snapshot_started_unix'],'finished_unix':time.time()}
                write_receipt(fd,'PROTECTION_COMPLETION.json',s.canonical(completion))
        finally:
            if created is not None:os.close(created)
            os.close(fd)
    print('S7 Dateirestore:',receipt['status'],'— vollständiger Attributvergleich; E1 bleibt HOLD.')
    return 0 if receipt['status']=='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('S7 Dateirestore abgebrochen:',str(error) if isinstance(error,Denied) else type(error).__name__)
        raise SystemExit(1)
