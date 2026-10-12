"""Offline deterministic capsule builder, never fetches or touches the host."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))

import tu1nz_control_recovery_contract as c


def git(root,*args):
    result=subprocess.run(['/usr/bin/git','--no-optional-locks','-C',str(root),'-c','core.fsmonitor=false',
        '-c','core.hooksPath=/dev/null',*args],capture_output=True,timeout=30,
        env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0',
             'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null'})
    c.require(result.returncode==0,'SOURCE_GIT_READ_RED');return result.stdout


def build_capsule(root,target=None):
    target=c.TARGET if target is None else target
    origin=git(root,'remote','get-url','origin').decode().strip().removesuffix('.git')
    if origin.startswith('git@github.com:'):origin='https://github.com/'+origin[len('git@github.com:'):]
    c.require(origin==target['repository'],'TARGET_ORIGIN_RED')
    c.require(git(root,'rev-parse',target['commit']+'^{tree}').decode().strip()==target['tree'],'TARGET_BINDING_RED')
    objects={}
    def read(object_id):
        if object_id in objects:return
        kind=git(root,'cat-file','-t',object_id).decode().strip()
        raw=git(root,'cat-file',kind,object_id)
        c.require(c.oid(kind,raw)==object_id,'OBJECT_INVALID')
        objects[object_id]={'kind':kind,'data':base64.b64encode(raw).decode()}
        if kind=='tree':
            for _,_,child in c.tree_entries(raw):read(child)
        if kind=='commit':
            for header in raw.partition(b'\n\n')[0].splitlines():
                if header.startswith((b'tree ',b'parent ')):read(header.split()[1].decode())
    read(target['commit']);read(target['tree'])
    raw=c.canonical({'schema':c.SCHEMA+'_CAPSULE','target':target,'objects':objects})
    c.Capsule(raw,target)
    return raw


def save_new(path,raw):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    c.require(path.read_bytes()==raw,'CAPSULE_READBACK_RED')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();raw=build_capsule(args.source);save_new(args.output,raw)
    print(json.dumps({'target':c.TARGET,'capsule_sha256':c.digest(raw),'bytes':len(raw),
                      'host_executed':False,'host_historical_content_included':False,
                      'target_git_provenance_included':True}))
