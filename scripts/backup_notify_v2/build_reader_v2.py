"""Deterministic offline build. No privileged work or network access."""
from pathlib import Path
import base64
import hashlib
import io
import json
import zipfile

BASE=Path(__file__).resolve().parent

def build():
    stream=io.BytesIO()
    files={p.relative_to(BASE/'vendor').as_posix():p.read_bytes() for p in (BASE/'vendor'/'bashlex').glob('*.py')}
    files['BASHLEX_LICENSE']=(BASE/'vendor'/'BASHLEX_LICENSE').read_bytes()
    for name in ('tu1nz_backup_notify_v2_engine.py','reader_runtime.py','CALLER_BINDINGS.json','PARSER_MANIFEST.json'):
        files[name]=(BASE/name).read_bytes()
    manifest=json.loads(files['PARSER_MANIFEST.json'])
    for name,sha in manifest['files'].items():
        assert hashlib.sha256((BASE/name).read_bytes()).hexdigest()==sha
    with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2026,9,27,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16;z.writestr(info,data)
    blob=stream.getvalue();sha=hashlib.sha256(blob).hexdigest()
    template='''#!/usr/bin/python3
# Generated from the versioned v2 sources; includes GPLv3+ bashlex with license.
import base64, contextlib, fcntl, hashlib, importlib, io, json, os, sys, zipfile
BUNDLE_SHA = SHA_VALUE
BUNDLE = BLOB_VALUE

def load_bundle():
    data=base64.b64decode(BUNDLE,validate=True)
    if hashlib.sha256(data).hexdigest()!=BUNDLE_SHA:raise ValueError('bundle_hash')
    sys.dont_write_bytecode=True
    if any(n=='bashlex' or n.startswith('bashlex.') for n in sys.modules):raise ValueError('parser_already_loaded')
    fd=os.memfd_create('tu1nz-parser-v2',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    with os.fdopen(os.dup(fd),'wb') as f:f.write(data);f.flush()
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
    sys.path.insert(0,'/proc/self/fd/'+str(fd))
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        parser=importlib.import_module('bashlex')
        engine=importlib.import_module('tu1nz_backup_notify_v2_engine')
        runtime=importlib.import_module('reader_runtime')
    with zipfile.ZipFile(io.BytesIO(data)) as z:binding=json.loads(z.read('CALLER_BINDINGS.json'))
    return fd,parser,engine,runtime,binding

if __name__=='__main__':
    if os.geteuid()!=0 or len(sys.argv)!=1:raise SystemExit(77)
    try:
        fd,parser,engine,runtime,binding=load_bundle()
        raise SystemExit(runtime.main(binding,engine,parser))
    except Exception as error:
        print('TU1NZ_BACKUP_NOTIFY_V2='+json.dumps({'version':'2.0.0','status':'INCOMPLETE','error_class':type(error).__name__}))
        raise SystemExit(2)
'''
    return template.replace('SHA_VALUE',repr(sha)).replace('BLOB_VALUE',repr(base64.b64encode(blob).decode())).encode()

if __name__=='__main__':
    data=build();path=BASE/'tu1nz_backup_notify_reader_v2.py'
    if path.exists():raise SystemExit('Refuse overwrite; backup and remove previous generated artifact explicitly')
    path.write_bytes(data);path.chmod(0o600)
    print(hashlib.sha256(data).hexdigest(),len(data))
