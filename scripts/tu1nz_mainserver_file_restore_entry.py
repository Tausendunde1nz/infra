"""Personal local sudo entry for the actual Rev4 file backup, no network.

Exact reviewed modules, real backup receipt and all blobs are checked before
creating the one fixed private root-owned restore directory. No Host paths are
used as local destinations. Failed entries remain occupied, never auto-retried.
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

INPUT=Path('/Users/daniel/Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101/execution/pre-stop-backup')
OUTPUT=Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/pre-stop-protection/public-rights-20261014-1')
SOURCE=Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')


def need(value,code):
    if not value:raise RuntimeError(code)


def read(path,limit):
    need(path.resolve(strict=True)==path,'ROOT_INPUT_CANONICAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600 and
             s.st_nlink==1 and s.st_size<=limit,'ROOT_INPUT_PROFILE')
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==s.st_size and all(tuple(getattr(v,k) for k in fields)==tuple(getattr(s,k) for k in fields)
             for v in (os.fstat(fd),path.lstat())),'ROOT_INPUT_CHANGED')
        return raw
    finally:os.close(fd)


def main():
    need(sys.platform=='darwin' and os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')=='501' and
         os.environ.get('SUDO_GID')=='20' and len(sys.argv)==1,'PERSONAL_MAC_ROOT_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope_raw=read(INPUT/'SCOPE.json',512*1024);scope=json.loads(scope_raw)
    review_raw=read(INPUT/'INDEPENDENT_REVIEW.json',65536);review=json.loads(review_raw)
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    need(review.get('verdict')=='PASS' and review.get('scope_sha256')==digest(scope_raw) and
         review.get('independent_of_implementer') is True and review.get('unresolved_findings')==[],
         'ROOT_INDEPENDENT_REVIEW_REQUIRED')
    name='tu1nz_mainserver_backup.py';raw=read(INPUT/'source'/name,256*1024)
    need(digest(raw)==scope['source_sha256'][name] and (SOURCE/name).read_bytes()==raw,'ROOT_BACKUP_SOURCE_CHANGED')
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader('bound_backup',None))
    exec(compile(raw,name,'exec'),module.__dict__)
    checked,scope_sha,review_sha,source=module.validate_inputs()
    need(checked==scope and module.OUTPUT==OUTPUT,'ROOT_SCOPE_CHANGED')
    need(Path(__file__).resolve(strict=True) in (INPUT/'source'/'tu1nz_mainserver_file_restore_entry.py',
         SOURCE/'tu1nz_mainserver_file_restore_entry.py') and
         Path(__file__).read_bytes()==source['tu1nz_mainserver_file_restore_entry.py'],'ROOT_ENTRY_SOURCE_CHANGED')
    f=module.load_source('tu1nz_mainserver_file_restore.py',source['tu1nz_mainserver_file_restore.py'])
    result_raw=read(OUTPUT/'RESULT.json',512*1024);previous=json.loads(result_raw)
    need(previous['scope_sha256']==scope_sha and previous['review_sha256']==review_sha and
         previous['status']=='REAL_DB_RESTORE_AND_FILE_READBACK_PASS_PRIVILEGED_FILE_RESTORE_PENDING' and
         previous['cleanup']==[],'ROOT_REAL_BACKUP_GATE')
    manifest_raw=read(OUTPUT/'files.json',512*1024);manifest=json.loads(manifest_raw)
    need(digest(manifest_raw)==previous['file_copy']['manifest_sha256'],'ROOT_FILE_MANIFEST_BINDING')
    blobs={row['sha256']:read(OUTPUT/'blobs'/row['sha256'],8*1024*1024)
           for row in manifest.values() if row['sha256'] is not None}
    f.profile(manifest,blobs,scope['reader_scope']['files'])
    need(OUTPUT.resolve(strict=True)==OUTPUT and OUTPUT.stat().st_uid==501 and
         stat.S_IMODE(OUTPUT.stat().st_mode)==0o700,'ROOT_OUTPUT_PARENT')
    fd=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    parent=None;receipt={'schema':'TU1NZ_REV4_REAL_PRIVILEGED_FILE_RESTORE_V1','status':'HOLD',
        'scope_sha256':scope_sha,'review_sha256':review_sha,'backup_result_sha256':digest(result_raw),
        'real_uid':os.getuid(),'effective_uid':os.geteuid(),'started_unix':time.time(),
        'source_sha256':scope['source_sha256']['tu1nz_mainserver_file_restore.py'],
        'host_contacted':False,'production_restore':False}
    try:
        # Root's personally entered local context creates this exact parent.
        # No pre-existing attribute is removed or exempted from comparison.
        os.mkdir('privileged-restore',0o700,dir_fd=fd)
        parent=os.open('privileged-restore',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        own=os.fstat(parent)
        need(own.st_uid==own.st_gid==0 and stat.S_IMODE(own.st_mode)==0o700,'ROOT_PRIVATE_RESTORE_PARENT')
        receipt['proof']=f.restore_private_files(parent,manifest,blobs,scope['reader_scope']['files'],
                                                 deadline=time.monotonic()+120)
        receipt['status']='PASS_REAL_FILES_AND_88_LIGHTING_OBJECTS'
    except BaseException as error:
        receipt['failure']=str(error) if isinstance(error,(f.Denied,RuntimeError)) else type(error).__name__
    finally:
        if parent is not None:os.close(parent)
        raw=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode()
        target=os.open('FILE_RESTORE_RESULT.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                       0o600,dir_fd=fd)
        try:
            offset=0
            while offset<len(raw):offset+=os.write(target,raw[offset:])
            os.fchown(target,501,20);os.fsync(target)
        finally:os.close(target)
        os.fsync(fd);os.close(fd)
        need(read(OUTPUT/'FILE_RESTORE_RESULT.json',512*1024)==raw,'ROOT_RECEIPT_READBACK')
    print('Dateirestore:',receipt['status'],'— unveränderter Attributvergleich; nur privater Mac-Prüfbereich.')
    return 0 if receipt['status'].startswith('PASS_') else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('Lokaler Restore abgebrochen:',type(error).__name__)
        raise SystemExit(1)
