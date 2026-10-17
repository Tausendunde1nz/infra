"""Private Application CI only: real artifact, no production state or providers.

The public operator's full execution/Owner path is a separate mandatory gate.
Only the exact checked-out private Application and reviewed public Infra enter;
the guest has no network, Host systemd, Docker socket, or credentials mounted.
"""
import sys
if __name__=='__main__' and (not sys.flags.isolated or not sys.dont_write_bytecode):
    sys.stderr.write('PRIVATE_RUNTIME_ISOLATED_NO_BYTECODE_ENTRY_REQUIRED\n')
    raise SystemExit(2)

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


def preimport_source(root,expected):
    """No repository module may run before the actual Source working-set gate."""
    if not re.fullmatch('[a-f0-9]{40}',expected):raise RuntimeError('PRIVATE_RUNTIME_SOURCE_SHA_RED')
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_GLOBAL':'/dev/null',
         'GIT_CONFIG_SYSTEM':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0'}
    def git(*args):
        r=subprocess.run(['/usr/bin/git','--no-optional-locks','--no-replace-objects',
            '-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',str(root),*args],
            capture_output=True,timeout=10,env=env)
        if r.returncode:raise RuntimeError('PRIVATE_RUNTIME_SOURCE_GIT_RED')
        return r.stdout
    if git('rev-parse','HEAD').decode().strip()!=expected:raise RuntimeError('PRIVATE_RUNTIME_SOURCE_SHA_RED')
    for args in (('status','--porcelain=v1','--untracked-files=all'),
                 ('ls-files','--others','--ignored','--exclude-standard','-z')):
        if git(*args):raise RuntimeError('PRIVATE_RUNTIME_UNREVIEWED_WORKING_SET_RED')
    return expected


PREIMPORT_BOUND_SHA=None
if __name__=='__main__':
    bootstrap=argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument('--infra-sha',required=True)
    selected,_=bootstrap.parse_known_args()
    try:PREIMPORT_BOUND_SHA=preimport_source(Path(__file__).resolve().parents[1],selected.infra_sha)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print(json.dumps({'green':False,'code':'PRIVATE_RUNTIME_SOURCE_PREIMPORT_RED','host_acceptance':False}))
        raise SystemExit(1)

# Imports below are reached by the receipt-producing CLI ONLY after the exact
# SHA/clean tracked, untracked AND ignored working-set check. Unit-test import
# is not a receipt-producing entry; main() rejects an unbound imported call.
sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_public_runtime_artifact as a
import tu1nz_public_runtime_build as build
import tu1nz_public_operator_ci as native


def source_roles(application_head,application_tree,workflow_head,event_head):
    a.require((application_head,application_tree)==a.APP,'ARTIFACT_CHECKOUT_COMMIT_TREE')
    a.require(type(workflow_head) is str and re.fullmatch('[a-f0-9]{40}',workflow_head) and
              workflow_head==event_head,'WORKFLOW_CARRIER_HEAD_BINDING')
    return {'application_commit':application_head,'application_tree':application_tree,
            'application_workflow_head':workflow_head}


def git_read(root,*argv):
    return native.command(['/usr/bin/git','-C',str(root),*argv]).decode().strip()


def checkout_roles(infra_source,application_source,workflow_source,expected_infra,event_head):
    """Three distinct roots: actual tool Source, artifact Source, workflow carrier."""
    a.require(re.fullmatch('[a-f0-9]{40}',expected_infra) and infra_source!=workflow_source and
        application_source.resolve()==workflow_source/'canonical-runtime-r5','EXACT_SOURCE_CHECKOUT')
    actual_infra=git_read(infra_source,'rev-parse','HEAD')
    a.require(actual_infra==expected_infra and not git_read(infra_source,'status','--porcelain') and
        not git_read(infra_source,'ls-files','--others','--ignored','--exclude-standard','-z'),
              'EXACT_INFRA_SOURCE_CHECKOUT')
    roles=source_roles(git_read(application_source,'rev-parse','HEAD'),
        git_read(application_source,'rev-parse','HEAD^{tree}'),git_read(workflow_source,'rev-parse','HEAD'),event_head)
    return actual_infra,roles


def validate_proof(raw,receipt):
    a.require(len(raw)<=16384,'ACTUAL_REPORT_BOUND')
    p=a.parse(raw.strip())
    a.require(set(p)=={'schema','artifact_sha256','receipt_sha256','source_manifest_sha256','objects','units',
        'historical_sentinel_unchanged','host_acceptance','provider_actions','operator_owner_acceptance'} and
        p['schema']=='TU1NZ_PUBLIC_RUNTIME_ACTUAL_NATIVE_R5_V1' and
        p['artifact_sha256']==receipt['archive_sha256'] and
        p['receipt_sha256']==a.sha(a.canonical(receipt)) and p['source_manifest_sha256']==a.SOURCE_MANIFEST and
        p['objects']==len(receipt['objects']) and p['historical_sentinel_unchanged'] is True and
        p['host_acceptance'] is False and p['provider_actions'] is False and
        p['operator_owner_acceptance']=='SEPARATE_MANDATORY_NATIVE_GATE','ACTUAL_REPORT_BINDING')
    a.require(type(p['units']) is list and len(p['units'])==3,'ACTUAL_UNITS')
    for i,row in enumerate(p['units']):
        a.require(set(row)=={'unit_index','http_sha256','same_first_invocation','kernel_groups_empty_caps_zero',
            'actual_readonly_artifact_view'} and type(row['unit_index']) is int and row['unit_index']==i and
            re.fullmatch('[a-f0-9]{64}',row['http_sha256']) and row['same_first_invocation'] is True and
            row['kernel_groups_empty_caps_zero'] is True and row['actual_readonly_artifact_view'] is True,
            'ACTUAL_UNIT_PROOF')
    return p


def main():
    p=argparse.ArgumentParser();p.add_argument('--application',type=Path,required=True)
    p.add_argument('--infra-sha',required=True);p.add_argument('--image',required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    a.require(PREIMPORT_BOUND_SHA==args.infra_sha,'RECEIPT_REQUIRES_PREIMPORT_SOURCE_GATE')
    os.umask(0o077);infra_source=Path(__file__).resolve().parents[1]
    out=args.output.absolute();created=False;container=None;owner=uuid.uuid4().hex;stage='admission'
    result={'schema':'TU1NZ_PUBLIC_RUNTIME_PRIVATE_CI_R5_V1','green':False,'host_acceptance':False}
    try:
        event=a.parse(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        a.require(os.environ.get('GITHUB_ACTIONS')=='true' and
            os.environ.get('GITHUB_REPOSITORY')=='Tausendunde1nz/adult-publishing-core' and
            event['repository']['private'] is True and event['repository']['full_name']==os.environ['GITHUB_REPOSITORY'],
            'PRIVATE_APPLICATION_JOB_REQUIRED')
        if 'pull_request' in event:
            a.require(event['pull_request']['head']['repo']['full_name']==os.environ['GITHUB_REPOSITORY'],
                      'NO_FORK_PRIVATE_ARTIFACT')
        workflow_source=Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        actual_infra,roles=checkout_roles(infra_source,args.application,workflow_source,args.infra_sha,
            event['pull_request']['head']['sha'] if 'pull_request' in event else os.environ['GITHUB_SHA'])
        parent=Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        a.require(out.parent==parent and not out.exists() and not out.is_symlink(),'PRIVATE_CREATE_ONLY_OUTPUT')
        out.mkdir(mode=0o700);created=True;cache=out/'inputs';cache.mkdir(mode=0o700)
        inputs=a.parse((infra_source/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        a.require(a.sha(a.canonical(inputs))==a.INPUTS_SHA,'REVIEWED_INPUT_LOCK')
        stage='authenticated-inputs'
        for row in [inputs['python'],*inputs['wheels']]:a.exclusive(cache/row['filename'],build.fetch(row))
        stage='offline-build'
        source=a.git_source(args.application)
        vendor=a.private_read(cache/inputs['python']['filename'])
        wheels={r['filename']:a.private_read(cache/r['filename']) for r in inputs['wheels']}
        raw,receipt=a.assemble(source,vendor,wheels,inputs)
        second,other=a.assemble(source,vendor,wheels,inputs)
        a.require(raw==second and a.canonical(receipt)==a.canonical(other),'OFFLINE_REBUILD_DIFFERED')
        a.inspect_archive(raw,receipt)
        artifact=out/'artifact';artifact.mkdir(mode=0o700)
        a.exclusive(artifact/'runtime.tar.gz',raw);a.exclusive(artifact/'RUNTIME_ARTIFACT.json',a.canonical(receipt))
        stage='isolated-native'
        image_id=native.command(['/usr/bin/docker','image','inspect','--format','{{.Id}}',args.image]).decode().strip()
        a.require(re.fullmatch('sha256:[a-f0-9]{64}',image_id),'FRESH_IMAGE_ID')
        container='tu1nz-public-runtime-private-'+owner
        argv=['/usr/bin/docker','create','--name',container,'--label','tu1nz.private-ci.owner='+owner,
            '--network','none','--privileged','--cgroupns=private','--env','container=docker',
            '--memory','2048m','--cpus','2','--pids-limit','512','--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',
            '--mount','type=bind,src='+str(infra_source)+',dst=/source,readonly',
            '--mount','type=bind,src='+str(artifact)+',dst=/artifact,readonly',args.image]
        native.command(argv,timeout=30)
        state=json.loads(native.command(['/usr/bin/docker','inspect',container]))[0]
        a.require(state['Image']==image_id and state['HostConfig']['NetworkMode']=='none' and
            state['HostConfig']['CgroupnsMode']=='private' and
            sorted((m['Source'],m['Destination'],m['RW']) for m in state['Mounts'] if m['Type']=='bind')==
            sorted(((str(infra_source),'/source',False),(str(artifact),'/artifact',False))),'ACTUAL_GUEST_BOUNDARY')
        native.command(['/usr/bin/docker','start',container],timeout=30);native.ready(container)
        code,proof=native.boundary.bounded(['/usr/bin/docker','exec',container,'/usr/bin/python3','-I','-B',
            '/source/tests/public_runtime_actual_native.py','--receipt-sha256',a.sha(a.canonical(receipt))],timeout=180)
        if code!=0:
            # Public fixed stage/type only; never child traceback/configuration.
            try:
                error=a.parse(proof.strip())['actual_runtime_failure']
                if error['stage'] in ('boundary','artifact','fixture','imports','units','start-0','start-1','start-2','complete'):
                    result['native_stage']=error['stage']
                if error['type'] in native.SAFE_FAILURE_TYPES:result['native_type']=error['type']
            except (ValueError,KeyError,TypeError):pass
        a.require(code==0,'ACTUAL_NATIVE_RUNTIME_RED')
        actual=validate_proof(proof,receipt)
        a.exclusive(out/'ACTUAL_NATIVE_PROOF.json',a.canonical(actual))
        result.update(green=True,infra_sha=actual_infra,**roles,
            artifact_sha256=a.sha(raw),receipt_sha256=a.sha(a.canonical(receipt)),
            inputs_sha256=a.INPUTS_SHA,offline_rebuild_byte_equal=True,
            actual_native_proof_sha256=a.sha(a.canonical(actual)))
    except BaseException as error:
        result.update(stage=stage,code=str(error) if type(error) is a.Denied else 'PRIVATE_RUNTIME_CI_RED')
    finally:
        if container is not None:
            try:native.boundary.cleanup_container(container,owner)
            except BaseException:result.update(green=False,cleanup='OWNED_GUEST_CLEANUP_RED')
    if created and out.is_dir() and not out.is_symlink():
        a.exclusive(out/'CI_RECEIPT.json',a.canonical(result))
    print(json.dumps(result,sort_keys=True))
    return 0 if result['green'] else 1


if __name__=='__main__':
    with native.boundary.interrupted():raise SystemExit(main())
