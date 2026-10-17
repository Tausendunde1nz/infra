"""Finite deterministic runtime assembly; never a Host grant or installer.

Only canonical Git blobs and individually pinned upstream distributions enter.
No build-time import/execution of Application, wheels or the supplied CPython.
Output is a private relocatable-byte archive for ONE separately approved root.
Original runtime provenance is neither required nor manufactured by this build.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import zipfile

APP = ('93555d8a141caf8ace33522f9340d30bfc47d2bb', '1e8a644115127818f394b6f9d24f31826e04ecba')
SOURCE_MANIFEST = '23e7ee9731ff3ae245099280a60681c7919b7361794ec32b7acd6ed9f71693d6'
INPUTS_SHA = '97b1dc842f14feefb36135bc396b5d9334d22ba3fe8790293248870fca631cae'
ROOT = '/opt/tu1nz_repos/public-web-runtime-r5/93555d8a141caf8ace33522f9340d30bfc47d2bb'
VIEW = '/opt/tu1nz_repos/adult-publishing-core'
EPOCH = 1791849600  # Fixed output metadata; not a historical observation timestamp.
MAX_INPUT = 64*1024*1024
MAX_TOTAL = 512*1024*1024
MAX_MEMBER = 32*1024*1024
MAX_OBJECTS = 16384
ENTRYPOINTS = {'tu1nz-public-s7': 'tu1nz_public_s7.runtime',
               'tu1nz-public-s8-landing': 'tu1nz_public_s8.landing'}


class Denied(RuntimeError):
    def __init__(self,code):
        self.primary='PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_RUNTIME_'+code.removeprefix('PUBLIC_RUNTIME_')
        super().__init__(code)


def require(value, code):
    if not value:
        raise Denied('PUBLIC_RUNTIME_'+code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def overlay():
    return ('[Service]\n# R5: private read-only service view; historical Host checkout unchanged.\n'
        'BindReadOnlyPaths='+ROOT+'/app:'+VIEW+'\nReadOnlyPaths='+ROOT+'\n').encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for k, v in rows:
            require(k not in value, 'DUPLICATE_JSON')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'JSON_CONSTANT'))


def relative(name):
    p = PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and '..' not in p.parts and
            str(p) == name and '\\' not in name and '\x00' not in name, 'MEMBER_PATH')
    return p


def private_read(path, *, limit=MAX_INPUT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.geteuid() and
                stat.S_IMODE(a.st_mode) == 0o600 and 0 <= a.st_size <= limit, 'PRIVATE_INPUT')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read(limit+1)
        b = os.fstat(fd); named = os.lstat(path)
        require(len(raw) == a.st_size and
                (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns) ==
                (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and
                (named.st_dev,named.st_ino) == (a.st_dev,a.st_ino), 'INPUT_CHANGED')
        return raw
    finally:
        os.close(fd)


def exclusive(path, raw):
    path = Path(path)
    require(path.parent.resolve(strict=True) == path.parent and
            path.parent.stat().st_uid == os.geteuid() and
            stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'PRIVATE_EXISTING_OUTPUT_PARENT')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)
    require(private_read(path, limit=max(MAX_INPUT,len(raw))) == raw, 'OUTPUT_READBACK')


def git_source(repo):
    def git(*args):
        env = {'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'GIT_NO_LAZY_FETCH':'1',
               'GIT_OPTIONAL_LOCKS':'0', 'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_CONFIG_SYSTEM':'/dev/null',
               'GIT_NO_REPLACE_OBJECTS':'1', 'GIT_TERMINAL_PROMPT':'0'}
        return subprocess.check_output(['/usr/bin/git','--no-optional-locks','--no-replace-objects',
            '-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(repo),*args],
            env=env, stderr=subprocess.DEVNULL, timeout=30)
    require(git('remote','get-url','origin').decode().strip() in
            ('https://github.com/Tausendunde1nz/adult-publishing-core.git',
             'https://github.com/Tausendunde1nz/adult-publishing-core',
             'git@github.com:Tausendunde1nz/adult-publishing-core.git'), 'CANONICAL_GIT_ORIGIN')
    require(git('rev-parse',APP[0]+'^{tree}').decode().strip() == APP[1], 'CANONICAL_GIT_TREE')
    rows = {}
    for record in git('ls-tree','-r','-z',APP[0]).split(b'\0'):
        if not record: continue
        header, name = record.split(b'\t',1); mode, kind, oid = header.split()
        require(kind == b'blob' and mode in (b'100644',b'100755'), 'CANONICAL_SOURCE_TYPE')
        key = name.decode(); relative(key)
        rows[key] = git('cat-file','blob',oid.decode())
    manifest = {k:{'kind':'file','sha256':sha(v)} for k,v in rows.items()}
    require(len(rows) == 650 and sha(canonical(manifest)) == SOURCE_MANIFEST, 'CANONICAL_SOURCE_MANIFEST')
    return rows


class Assembly:
    def __init__(self):
        self.rows = {}; self.total = 0

    def add(self, name, *, raw=None, target=None, executable=False, directory=False):
        p = relative(name)
        if str(p.parent) != '.' and str(p.parent) not in self.rows:
            self.add(str(p.parent), directory=True)
        if str(p.parent) != '.':
            require(self.rows[str(p.parent)]['kind']=='directory','PARENT_NOT_DIRECTORY')
        if name in self.rows:
            require(directory and self.rows[name]['kind'] == 'directory', 'DUPLICATE_MEMBER')
            return
        require(len(self.rows) < MAX_OBJECTS, 'OBJECT_BOUND')
        if directory:
            row = {'kind':'directory','mode':0o555}
        elif target is not None:
            require(type(target) is str and target and '\x00' not in target and '\\' not in target,
                    'LINK_TARGET')
            # Absolute links are generated only for the three venv aliases.
            if target.startswith('/'):
                require(name in ('app/.venv/bin/python','app/.venv/bin/python3','app/.venv/bin/python3.12') and
                        target == ROOT+'/python/bin/python3.12', 'LINK_ESCAPE')
            else:
                parts = list(p.parent.parts)
                for part in PurePosixPath(target).parts:
                    if part == '..': require(parts, 'LINK_ESCAPE'); parts.pop()
                    elif part != '.': parts.append(part)
                require(parts and parts[0] == 'python', 'LINK_ESCAPE')
            row = {'kind':'link','target':target,'mode':0o777}
        else:
            require(type(raw) is bytes and len(raw) <= MAX_MEMBER, 'FILE_BOUND')
            self.total += len(raw); require(self.total <= MAX_TOTAL, 'EXPANSION_BOUND')
            row = {'kind':'file','sha256':sha(raw),'size':len(raw),'mode':0o555 if executable else 0o444,'raw':raw}
        self.rows[name] = row

    def archive(self):
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0,filename='',compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as tar:
                for name, row in sorted(self.rows.items()):
                    info = tarfile.TarInfo(name); info.uid=info.gid=0;info.uname=info.gname='';info.mtime=EPOCH;info.mode=row['mode']
                    if row['kind'] == 'directory': info.type=tarfile.DIRTYPE
                    elif row['kind'] == 'link': info.type=tarfile.SYMTYPE;info.linkname=row['target']
                    else: info.size=row['size']
                    tar.addfile(info,io.BytesIO(row['raw']) if row['kind']=='file' else None)
        raw=stream.getvalue();require(len(raw)<=MAX_INPUT,'ARCHIVE_BOUND')
        return raw

    def manifest(self):
        return {k:{f:v for f,v in row.items() if f!='raw'} for k,row in sorted(self.rows.items())}


def validate_receipt(receipt, inputs):
    require(sha(canonical(inputs)) == INPUTS_SHA and
        set(receipt) == {'schema','root','service_view','application','inputs_sha256','python','wheels','objects',
                        'archive_sha256','archive_bytes','expanded_file_bytes','old_runtime_origin',
                        'old_runtime_return','host_authority','r2_slot_consumed'} and
        receipt['schema']=='TU1NZ_PUBLIC_RUNTIME_ARTIFACT_R5_V1' and
        receipt['root']==ROOT and receipt['service_view']==VIEW and
        canonical(receipt['application'])==canonical(inputs['application']) and
        canonical(receipt['python'])==canonical(inputs['python']) and
        canonical(receipt['wheels'])==canonical(inputs['wheels']) and receipt['inputs_sha256']==INPUTS_SHA and
        receipt['old_runtime_origin']=='UNKNOWN_NOT_ADOPTED' and
        receipt['old_runtime_return'] is False and receipt['host_authority'] is False and
        receipt['r2_slot_consumed'] is False, 'REPLACEMENT_RECEIPT_BINDING')
    objects=receipt['objects']
    require(type(objects) is dict and 0 < len(objects) <= MAX_OBJECTS and
        type(receipt['archive_bytes']) is int and 0 < receipt['archive_bytes'] <= MAX_INPUT and
        type(receipt['expanded_file_bytes']) is int and 0 < receipt['expanded_file_bytes'] <= MAX_TOTAL,
        'REPLACEMENT_SIZE_BOUND')
    source={};total=0
    for name,row in objects.items():
        p=relative(name)
        require(p.parts[0] in ('python','app') and
                (str(p.parent)=='.' or objects.get(str(p.parent),{}).get('kind')=='directory'),
                'REPLACEMENT_OBJECT_NAMESPACE')
        if row.get('kind')=='file':
            require(set(row)=={'kind','mode','sha256','size'} and type(row['mode']) is int and row['mode'] in (0o444,0o555) and
                type(row['size']) is int and 0 <= row['size'] <= MAX_MEMBER and
                type(row['sha256']) is str and len(row['sha256'])==64 and
                all(c in '0123456789abcdef' for c in row['sha256']), 'REPLACEMENT_FILE_PROFILE')
            total+=row['size']
            if name.startswith('app/') and not name.startswith('app/.venv/'):
                source[name[4:]]={'kind':'file','sha256':row['sha256']}
        elif row.get('kind')=='directory':
            require(row=={'kind':'directory','mode':0o555} and type(row['mode']) is int,'REPLACEMENT_DIRECTORY_PROFILE')
        else:
            require(row.get('kind')=='link' and set(row)=={'kind','mode','target'} and type(row['mode']) is int and row['mode']==0o777,
                    'REPLACEMENT_LINK_PROFILE')
            proof=Assembly();proof.add(name,target=row['target'])
    require(total==receipt['expanded_file_bytes'] and len(source)==650 and
        sha(canonical(source))==SOURCE_MANIFEST and
        objects.get('python/bin/python3.12',{}).get('kind')=='file' and
        all(objects.get('app/.venv/bin/'+name,{}).get('kind')=='file' for name in ENTRYPOINTS),
        'REPLACEMENT_SOURCE_OR_ENTRYPOINTS')
    return receipt


def inspect_archive(raw, receipt):
    require(len(raw)==receipt['archive_bytes'] and sha(raw)==receipt['archive_sha256'],
            'REPLACEMENT_ARCHIVE_HASH')
    rows={};expanded=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for member in archive:
            name=member.name;relative(name)
            require(name not in rows and name in receipt['objects'] and len(rows)<MAX_OBJECTS and
                member.uid==member.gid==0 and member.uname==member.gname=='' and
                member.mtime==EPOCH and not set(member.pax_headers)-{'path','linkpath'} and
                ('path' not in member.pax_headers or member.pax_headers['path']==name or
                 member.isdir() and member.pax_headers['path']==name+'/') and
                ('linkpath' not in member.pax_headers or
                 member.issym() and member.pax_headers['linkpath']==member.linkname),
                'REPLACEMENT_TAR_HEADER')
            expected=receipt['objects'][name]
            if member.isdir(): row={'kind':'directory','mode':member.mode}
            elif member.issym():row={'kind':'link','mode':member.mode,'target':member.linkname}
            else:
                require(member.isfile() and 0<=member.size<=MAX_MEMBER,'REPLACEMENT_TAR_TYPE')
                expanded+=member.size;require(expanded<=MAX_TOTAL,'REPLACEMENT_EXPANSION_BOUND')
                data=archive.extractfile(member).read(MAX_MEMBER+1)
                require(len(data)==member.size,'REPLACEMENT_TAR_SHORT_READ')
                row={'kind':'file','mode':member.mode,'size':len(data),'sha256':sha(data)}
            require(row==expected,'REPLACEMENT_MEMBER_BINDING');rows[name]=row
    require(rows==receipt['objects'] and expanded==receipt['expanded_file_bytes'],
            'REPLACEMENT_COMPLETE_NAMESPACE')


def assemble(source, python_raw, wheel_rows, inputs):
    require(sha(canonical(inputs))==INPUTS_SHA and inputs['schema']=='TU1NZ_PUBLIC_RUNTIME_INPUTS_R5_V1' and
            (inputs['application']['commit'],inputs['application']['tree'])==APP and
            inputs['application']['manifest_sha256']==SOURCE_MANIFEST and
            inputs['python']['version']=='3.12.15' and
            inputs['python']['platform']=='x86_64-unknown-linux-gnu', 'INPUT_LOCK')
    expected={k:{'kind':'file','sha256':sha(v)} for k,v in source.items()}
    require(len(source)==650 and sha(canonical(expected))==SOURCE_MANIFEST,'SOURCE_BINDING')
    require(len(python_raw)==inputs['python']['bytes'] and sha(python_raw)==inputs['python']['sha256'],'PYTHON_INPUT_HASH')
    a=Assembly()
    with tarfile.open(fileobj=io.BytesIO(python_raw),mode='r:gz') as archive:
        count=0
        for member in archive:
            count+=1;require(count<=MAX_OBJECTS and member.name.startswith('python/'),'PYTHON_MEMBER_SCOPE')
            name=member.name.rstrip('/');relative(name)
            require(not member.pax_headers and not member.mode & 0o7000,'PYTHON_METADATA')
            if member.isdir(): a.add(name,directory=True)
            elif member.issym():a.add(name,target=member.linkname)
            else:
                require(member.isfile() and member.size<=MAX_MEMBER,'PYTHON_MEMBER_TYPE_OR_BOUND')
                data=archive.extractfile(member).read(MAX_MEMBER+1)
                require(len(data)==member.size,'PYTHON_SHORT_READ');a.add(name,raw=data,executable=bool(member.mode&0o111))
    require('python/bin/python3.12' in a.rows and a.rows['python/bin/python3.12']['kind']=='file','PYTHON_EXECUTABLE_MISSING')
    for name,raw in sorted(source.items()):a.add('app/'+name,raw=raw)
    locks=source['requirements-m2.lock']+source['requirements-s5.lock']
    allowed=set(re.findall(rb'--hash=sha256:([0-9a-f]{64})',locks))
    require(set(wheel_rows)=={w['filename'] for w in inputs['wheels']} and len(wheel_rows)==7,'WHEEL_SET')
    for row in inputs['wheels']:
        raw=wheel_rows[row['filename']]
        require(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and row['sha256'].encode() in allowed,'WHEEL_HASH_NOT_CANONICAL_LOCK')
        with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
            infos=wheel.infolist();require(len(infos)<=MAX_OBJECTS,'WHEEL_MEMBER_BOUND')
            seen=set()
            for member in infos:
                name=member.filename.rstrip('/');relative(name)
                require(name not in seen and not member.flag_bits&1 and
                        not stat.S_ISLNK(member.external_attr>>16) and
                        not (member.external_attr>>16)&0o7000 and
                        not any(part.endswith('.data') for part in PurePosixPath(name).parts),'WHEEL_MEMBER_PROFILE')
                seen.add(name)
                dest='app/.venv/lib/python3.12/site-packages/'+name
                if member.is_dir():a.add(dest,directory=True)
                else:
                    require(member.file_size<=MAX_MEMBER,'WHEEL_MEMBER_SIZE')
                    data=wheel.read(member);require(len(data)==member.file_size,'WHEEL_SHORT_READ');a.add(dest,raw=data)
    for alias in ('python','python3','python3.12'):a.add('app/.venv/bin/'+alias,target=ROOT+'/python/bin/python3.12')
    a.add('app/.venv/pyvenv.cfg',raw=('home = '+ROOT+'/python/bin\ninclude-system-site-packages = false\nversion = 3.12.15\n').encode())
    for name,module in ENTRYPOINTS.items():
        a.add('app/.venv/bin/'+name,raw=('#!'+VIEW+'/.venv/bin/python\nimport sys\nsys.path.insert(0, '+repr(VIEW+'/src')+')\nfrom '+module+' import entrypoint\nraise SystemExit(entrypoint())\n').encode(),executable=True)
    raw=a.archive()
    receipt={'schema':'TU1NZ_PUBLIC_RUNTIME_ARTIFACT_R5_V1','root':ROOT,'service_view':VIEW,
        'application':inputs['application'],'inputs_sha256':sha(canonical(inputs)),
        'python':inputs['python'],'wheels':inputs['wheels'],'objects':a.manifest(),
        'archive_sha256':sha(raw),'archive_bytes':len(raw),'expanded_file_bytes':a.total,
        'old_runtime_origin':'UNKNOWN_NOT_ADOPTED','old_runtime_return':False,
        'host_authority':False,'r2_slot_consumed':False}
    return raw,receipt
