"""Control-only recovery of a separate immutable operational source view.

Never replaces the historical Control root/guard, restores an old marker,
imports S12 recovery, or starts a consumer. Production paths are finite.
The privileged executor/kernel are TCB, not all UID-zero file writers.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zlib

SCHEMA = 'TU1NZ_CONTROL_ONLY_RECOVERY_R1'
SLOT = 'control-only-recovery-20261012-1'
ANCHOR = Path('/opt/tu1nz_repos/control-only-recovery-r1')
HISTORICAL = Path('/opt/tu1nz_repos/control')
APPLICATION = Path('/opt/tu1nz_repos/adult-publishing-core')
HISTORY = Path('/etc/tu1nz/adult-commercial-s12-1-private/state')
TARGET = {'repository': 'https://github.com/Tausendunde1nz/control',
          'commit': '2281b2b397c017bc370ba108eab3dc00c989eaa5',
          'tree': '3d52fe0898238e1132d8947a7e171d8086982170'}
HISTORICAL_COMMIT = 'b44a3a7e6162a2cc01ef0eb0da564bec68090adc'
HISTORICAL_TREE = '477e63c6818d42473a9e4400b83faedead7524bc'
MACHINE = 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae'
# CURRENT R6 endpoint identities, not historical inode continuity.
R6_ROOT = (2049, 1283349)
R6_GUARD = (2049, 1459619)
R6_QUARANTINE = (2049, 1453930)
ROOT_ORIGINS = {'https://github.com/Tausendunde1nz/infra',
                'https://github.com/Tausendunde1nz/control'}
MAX_NODES = 20000
MAX_BYTES = 512*1024*1024
MAX_OBJECT = 16*1024*1024
HISTORY_HASHES = {
 'repository-barrier.json':'8e2bb8ec334584d2a87e7b1d5b0f01fcf9463ed37281510fa56a9e49d89250ae',
 'repository-barrier.r12-bindings.json':'68f815b7fccc483f9c74aa9535b23fffb865ed1a71fddfd30e708590d1393dbd',
 'repository-barrier.r12-abort.json':'ca5945059fb8cebc4c3ab91d803354d7eef3dae4c27f1af6edab10499dd28ca5',
 'deployment-attempted.json':'30189b22f290361e901ac4f6b0af95ebc75424014ff190fb86cc9600c5ab680c'}
ABSENT_MARKERS = ('repository-barrier.r15-containment.json','repository-barrier.r15-containment-progress.json',
 'repository-barrier.r15-contained.json','repository-barrier.r15-containment-failed.json','r13-followup-1.consumed.json')


class RecoveryError(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise RecoveryError('CONTROL_RECOVERY_'+code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def failure(error):
    code = str(error)
    value={'type': type(error).__name__, 'code': code if re.fullmatch(
        r'(CONTROL_RECOVERY_|S8_EXECUTION_)[A-Z0-9_]{1,160}', code) else 'UNKNOWN',
        'errno': getattr(error, 'errno', None)}
    underlying=getattr(error,'_s8_read_failure',None)
    if isinstance(underlying,dict):
        value['underlying_read']={key:underlying.get(key) for key in ('type','code','errno')}
    return value


def relative(name):
    require(type(name) is str and name and '\x00' not in name and '\\' not in name,
            'UNSAFE_NAME')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and
            all(p not in ('.', '..', '.git') for p in path.parts), 'UNSAFE_NAME')
    require(len(name.encode()) < 4096 and len(path.parts) < 64, 'UNSAFE_NAME')
    return name


def oid(kind, raw):
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def tree_entries(raw,*,historical=False):
    result=[];pos=0;seen=set()
    while pos < len(raw):
        end=raw.find(b'\0',pos)
        require(end >= 0 and end+21 <= len(raw),'TREE_INVALID')
        mode,sep,name=raw[pos:end].partition(b' ')
        supported=(b'40000',b'100644',b'100755',b'120000') if historical else (b'40000',b'100644',b'100755')
        require(sep and mode in supported, 'TREE_MODE_UNSUPPORTED')
        name=name.decode('utf-8');relative(name)
        require('/' not in name and name not in seen,'TREE_INVALID');seen.add(name)
        result.append((mode.decode(),name,raw[end+1:end+21].hex()));pos=end+21
    return result


def index_bytes(files):
    """Git index v2, pinned immutable main; no Git writer on host."""
    out=bytearray(b'DIRC'+struct.pack('>II',2,len(files)))
    for name, record in sorted(files.items()):
        raw=name.encode();mode=int(record['mode'],8)
        entry=struct.pack('>10I',0,0,0,0,0,0,mode,0,1001,len(record['bytes']))
        entry+=bytes.fromhex(record['oid'])+struct.pack('>H',min(len(raw),0xfff))+raw+b'\0'
        entry+=b'\0'*((-len(entry))%8);out.extend(entry)
    return bytes(out)+hashlib.sha1(out).digest()


def index_entries(raw):
    require(len(raw)>=32 and raw[:4]==b'DIRC' and hashlib.sha1(raw[:-20]).digest()==raw[-20:],
            'INDEX_INVALID')
    version,count=struct.unpack('>II',raw[4:12]);require(version in (2,3) and count<=MAX_NODES,'INDEX_UNSUPPORTED')
    pos=12;records={}
    for _ in range(count):
        start=pos;require(pos+62<=len(raw)-20,'INDEX_INCOMPLETE')
        values=struct.unpack('>10I',raw[pos:pos+40]);object_id=raw[pos+40:pos+60].hex()
        flags=struct.unpack('>H',raw[pos+60:pos+62])[0];pos+=62
        require(not flags&0x3000 and not flags&0x4000,'INDEX_UNMERGED_OR_EXTENDED')
        end=raw.find(b'\0',pos);require(pos<=end<len(raw)-20,'INDEX_INCOMPLETE')
        name=raw[pos:end].decode('utf-8');relative(name)
        require(name not in records and values[6] in (0o100644,0o100755,0o120000),'INDEX_INVALID')
        pos=start+((end+1-start+7)//8)*8
        require(not any(raw[end+1:pos]),'INDEX_INVALID')
        records[name]={'oid':object_id,'mode':values[6]}
    # Mandatory lowercase extensions cannot be silently ignored (split/sparse index).
    while pos<len(raw)-20:
        require(pos+8<=len(raw)-20,'INDEX_INCOMPLETE')
        signature=raw[pos:pos+4];length=struct.unpack('>I',raw[pos+4:pos+8])[0]
        require(signature[:1].isupper() and pos+8+length<=len(raw)-20,'INDEX_UNSUPPORTED')
        pos+=8+length
    require(pos==len(raw)-20,'INDEX_INCOMPLETE')
    return records


class Capsule:
    """Whole target tree authenticated independently of origin or worktree claims."""
    def __init__(self, raw, expected=None):
        require(len(raw)<=MAX_BYTES,'CAPSULE_BOUND')
        value=json.loads(raw);self.target=expected if expected is not None else TARGET
        require(set(value)=={'schema','target','objects'} and value['schema']==SCHEMA+'_CAPSULE'
                and value['target']==self.target,'TARGET_BINDING_RED')
        require(type(value['objects']) is dict and 0<len(value['objects'])<=MAX_NODES,'CAPSULE_BOUND')
        self.raw=raw;self.sha256=digest(raw);self.objects={};self.files={};self.used=set();self.history_done=set()
        for object_id,record in value['objects'].items():
            require(re.fullmatch('[0-9a-f]{40}',object_id) and set(record)=={'kind','data'},'OBJECT_INVALID')
            require(record['kind'] in ('commit','tree','blob'),'OBJECT_INVALID')
            payload=base64.b64decode(record['data'],validate=True)
            require(len(payload)<=MAX_OBJECT and oid(record['kind'],payload)==object_id,'OBJECT_INVALID')
            self.objects[object_id]=(record['kind'],payload)
        kind,commit=self.get(self.target['commit']);require(kind=='commit','OBJECT_INVALID')
        require(commit.startswith(b'tree '+self.target['tree'].encode()+b'\n'),'TARGET_BINDING_RED')
        self.walk(self.target['tree'],'',set())
        self.bind_history(self.target['commit'],set())
        require(self.used==set(self.objects),'UNBOUND_OBJECTS')

    def get(self, object_id):
        require(object_id in self.objects,'OBJECT_MISSING');self.used.add(object_id)
        return self.objects[object_id]

    def walk(self, object_id, prefix, active):
        require(object_id not in active and len(active)<64,'TREE_CYCLE')
        kind,raw=self.get(object_id);require(kind=='tree','OBJECT_INVALID')
        for mode,name,child in tree_entries(raw):
            path=relative(prefix+name)
            if mode=='40000':self.walk(child,path+'/',active|{object_id})
            else:
                kind,data=self.get(child);require(kind=='blob' and path not in self.files,'OBJECT_INVALID')
                self.files[path]={'oid':child,'mode':mode,'bytes':data}

    def bind_history(self,object_id,active):
        require(object_id not in active and len(active)<500,'COMMIT_CYCLE_OR_BOUND')
        kind,raw=self.get(object_id);require(kind=='commit','OBJECT_INVALID')
        headers=raw.partition(b'\n\n')[0].splitlines()
        require(headers and re.fullmatch(b'tree [0-9a-f]{40}',headers[0]),'OBJECT_INVALID')
        self.bind_tree(headers[0][5:].decode(),set())
        for header in headers[1:]:
            if header.startswith(b'parent '):
                require(re.fullmatch(b'parent [0-9a-f]{40}',header),'OBJECT_INVALID')
                parent=header[7:].decode()
                if parent not in self.history_done:self.bind_history(parent,active|{object_id})
        self.history_done.add(object_id)

    def bind_tree(self,object_id,active):
        require(object_id not in active and len(active)<64,'TREE_CYCLE')
        kind,raw=self.get(object_id);require(kind=='tree','OBJECT_INVALID')
        for mode,_,child in tree_entries(raw):
            if mode=='40000':self.bind_tree(child,active|{object_id})
            else:
                kind,_=self.get(child);require(kind=='blob','OBJECT_INVALID')

    def release_files(self):
        files={name:(record['bytes'],0o550 if record['mode']=='100755' else 0o440)
               for name,record in self.files.items()}
        files['.git/HEAD']=(b'ref: refs/heads/main\n',0o440)
        for name in ('refs/heads/main','refs/remotes/origin/main'):
            files['.git/'+name]=((self.target['commit']+'\n').encode(),0o440)
        # No includes, filters, fsmonitor, hooks, helpers or historical checkout imports.
        config=('[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n'
                'logallrefupdates = false\n[remote "origin"]\nurl = '+self.target['repository']+'\n')
        files['.git/config']=(config.encode(),0o440)
        files['.git/index']=(index_bytes(self.files),0o440)
        for object_id,(kind,raw) in self.objects.items():
            data=zlib.compress(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw)
            files['.git/objects/'+object_id[:2]+'/'+object_id[2:]]=(data,0o440)
        return files


@dataclass(frozen=True)
class Layout:
    historical: Path
    anchor: Path
    preserved: tuple[Path,...]
    pin: tuple[int,int]
    guard_pin: tuple[int,int]
    quarantine_pin: tuple[int,int]
    host: str
    old_commit: str
    old_tree: str
    evidence_hashes: dict | None = None

    @classmethod
    def production(cls):
        return cls(HISTORICAL, ANCHOR,
                   (APPLICATION,APPLICATION/'.git',*(HISTORY/name for name in HISTORY_HASHES),
                    *(HISTORY/name for name in ABSENT_MARKERS)),
                   R6_ROOT,R6_GUARD,R6_QUARANTINE,MACHINE,HISTORICAL_COMMIT,HISTORICAL_TREE,
                   {str(HISTORY/name):digest for name,digest in HISTORY_HASHES.items()})
