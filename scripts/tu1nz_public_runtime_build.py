"""LOCAL Source artifact preparation. No SSH, Host execution, claim or sudo.

fetch authenticates pinned bytes from the named official upstream endpoints;
build is deterministic/offline and executes NO supplied runtime or Application.
Neither command makes a Host scope or calls the production operator.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_public_runtime_artifact as artifact

REPO=Path(__file__).resolve().parents[1]


class UpstreamOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        p=urllib.parse.urlsplit(url)
        artifact.require(p.scheme=='https' and p.hostname in
            ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com',
             'files.pythonhosted.org') and p.username is None and p.password is None,'UPSTREAM_REDIRECT')
        return super().redirect_request(request,file,code,message,headers,url)


def fetch(row):
    p=urllib.parse.urlsplit(row['url'])
    artifact.require(p.scheme=='https' and p.hostname in ('github.com','files.pythonhosted.org') and
                     p.username is None and p.password is None,'UPSTREAM_ENDPOINT')
    request=urllib.request.Request(row['url'],headers={'User-Agent':'TU1NZ-source-artifact-r5'})
    with urllib.request.build_opener(UpstreamOnly()).open(request,timeout=60) as response:
        raw=response.read(row['bytes']+1)
    artifact.require(len(raw)==row['bytes'] and artifact.sha(raw)==row['sha256'],'UPSTREAM_SIZE_OR_DIGEST')
    return raw


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('fetch','build'))
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--application-reference',type=Path)
    args=parser.parse_args();os.umask(0o077)
    artifact.require(Path.cwd().resolve()==REPO.resolve(),'ACTUAL_SOURCE_CWD')
    result=subprocess.run(['/opt/homebrew/bin/python3.12',
        '/Users/daniel/Developer/tu1nz/control-governance-v1.1/governance/preflight.py',
        '--cwd',str(Path.cwd())],capture_output=True,timeout=20)
    artifact.require(result.returncode==0 and b'GOVERNANCE_V1_1_ACTIVE' in result.stdout,'CANONICAL_PREFLIGHT_RED')
    inputs=artifact.parse((REPO/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
    artifact.require(artifact.sha(artifact.canonical(inputs))==artifact.INPUTS_SHA,'REVIEWED_INPUT_LOCK')
    cache=args.cache.absolute();artifact.require(cache.resolve(strict=True)==cache and
        cache.is_dir() and cache.stat().st_uid==os.geteuid() and
        cache.stat().st_mode&0o777==0o700,'PRIVATE_EXISTING_CACHE')
    rows=[inputs['python'],*inputs['wheels']]
    if args.operation=='fetch':
        artifact.require(args.output is None and args.application_reference is None,'FETCH_ARGUMENT_SCOPE')
        receipts=[]
        for row in rows:
            target=cache/row['filename'];artifact.require(target.parent==cache,'CACHE_FILENAME')
            if target.exists():
                raw=artifact.private_read(target);artifact.require(len(raw)==row['bytes'] and
                    artifact.sha(raw)==row['sha256'],'EXISTING_CACHE_MISMATCH_NO_REPLACE')
                state='EXISTING_PINNED_BYTES_READ_BACK'
            else:
                raw=fetch(row);artifact.exclusive(target,raw);state='FETCHED_PINNED_OFFICIAL_UPSTREAM_BYTES'
            receipts.append({'filename':row['filename'],'sha256':artifact.sha(raw),'bytes':len(raw),
                             'origin':row['url'],'state':state})
        proof={'schema':'TU1NZ_PUBLIC_RUNTIME_FETCH_R5_V1','inputs_sha256':artifact.INPUTS_SHA,
               'files':receipts,'host_authority':False,'slot_consumed':False}
        name=cache/'FETCH_RECEIPT.json'
        if name.exists():
            previous=artifact.parse(artifact.private_read(name))
            artifact.require(previous['inputs_sha256']==artifact.INPUTS_SHA and
                {(r['filename'],r['sha256'],r['bytes']) for r in previous['files']}==
                {(r['filename'],r['sha256'],r['bytes']) for r in receipts},'FETCH_RECEIPT_CONFLICT')
        else:artifact.exclusive(name,artifact.canonical(proof))
        print(json.dumps({'status':'UPSTREAM_INPUTS_PINNED_LOCAL_ONLY','files':len(rows),
                          'inputs_sha256':artifact.INPUTS_SHA,'host_access':False}));return
    artifact.require(args.output is not None and args.application_reference is not None,'BUILD_ARGUMENTS')
    out=args.output.absolute();artifact.require(not out.exists() and not out.is_symlink(),'CREATE_ONLY_BUILD_OUTPUT')
    artifact.require(out.parent.resolve(strict=True)==out.parent and out.parent.stat().st_uid==os.geteuid()
                     and out.parent.stat().st_mode&0o777==0o700,'PRIVATE_EXISTING_BUILD_PARENT')
    out.mkdir(mode=0o700)
    artifact.exclusive(out/'BUILD_INTENT.json',artifact.canonical({'inputs_sha256':artifact.INPUTS_SHA,
        'application':inputs['application'],'host_authority':False,'old_runtime_not_used':True}))
    source=artifact.git_source(args.application_reference)
    python=artifact.private_read(cache/inputs['python']['filename'])
    wheels={r['filename']:artifact.private_read(cache/r['filename']) for r in inputs['wheels']}
    raw,receipt=artifact.assemble(source,python,wheels,inputs)
    second,second_receipt=artifact.assemble(source,python,wheels,inputs)
    artifact.require(raw==second and receipt==second_receipt,'OFFLINE_REBUILD_NOT_IDENTICAL')
    artifact.exclusive(out/'runtime.tar.gz',raw)
    artifact.exclusive(out/'RUNTIME_ARTIFACT.json',artifact.canonical(receipt))
    proof={'schema':'TU1NZ_PUBLIC_RUNTIME_LOCAL_BUILD_R5_V1','artifact_sha256':artifact.sha(raw),
        'receipt_sha256':artifact.sha(artifact.canonical(receipt)),'inputs_sha256':artifact.INPUTS_SHA,
        'assembly_source_sha256':artifact.sha((REPO/'scripts/tu1nz_public_runtime_artifact.py').read_bytes()),
        'offline_rebuild_byte_equal':True,'supplied_code_executed':False,'host_authority':False,
        'functional_native_test':'REQUIRED_SEPARATE_NOT_CLAIMED_BY_ASSEMBLY'}
    artifact.exclusive(out/'BUILD_RECEIPT.json',artifact.canonical(proof))
    print(json.dumps({'status':'OFFLINE_ASSEMBLY_REPRODUCED_NOT_HOST_ADMISSION',
        'archive_sha256':artifact.sha(raw),'receipt_sha256':proof['receipt_sha256'],
        'objects':len(receipt['objects']),'archive_bytes':len(raw),'host_access':False}))


if __name__=='__main__':
    try:main()
    except (artifact.Denied,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'NOT_BUILT_NO_HOST_EFFECT','error_type':type(error).__name__,
            'code':str(error) if isinstance(error,artifact.Denied) else 'LOCAL_IO_OR_INPUT_RED'}))
        raise SystemExit(2)
