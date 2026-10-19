"""Finite private-source witness on an approved, fresh GitHub hosted runner.

Environment approval is enforced OUTSIDE this code by GitHub, before any job
step. This helper cannot approve itself or make arbitrary PR code trusted.
No secret, private source or child output is printed/uploaded/cached. Native
fixtures never receive credentials; only the pinned capsule is mounted.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_control_recovery_contract as c
from tu1nz_control_recovery_release import build_capsule,save_new

ENVIRONMENT='control-private-ci'
REPOSITORY='Tausendunde1nz/infra'
# Finite separately reviewed source PRs, never a generic same-repo exception.
# Environment required-reviewer approval still binds every actual exact SHA
# BEFORE any job/secret. PR226 extends public-service isolation source only;
# it does not change capsule, token repository scope or Host admission.
# PR227 is the separately reviewed opt-staging/Host-plan Source addendum.
# Keep exact PR membership; unchanged required reviewer approval still checks
# each actual SHA before secrets. No generic branch/fork or Host permission.
# PR228 is only the R3 stop/bootstrap sequencing Source delta. Existing exact
# SHA review and environment reviewer approval still precede ANY private input.
# PR229 is the finite production-adapter/owner-supervisor integration delta.
# It neither widens credential scope nor removes exact-SHA Environment review.
# PR230 is only its authorized post-CI fresh-read implementation correction.
# Membership is finite; independent review and Environment approval still bind
# EVERY actual SHA before any private input. No generic same-repo exception.
# PR231 is the finite prospective public-runtime replacement Source delta.
# The token still reads ONLY the same three Control blobs; actual-SHA review
# and required Environment approval remain mandatory before private input.
# PR232 is the finite pre-baseline synthetic policy-worker lifecycle fix.
# Same three pinned blobs, credential scope, exact-SHA review and required
# Environment approval; no generic PR, Host or production retry permission.
# PR233 is only the B data/Writer Source contract. No new private data scope:
# the same pinned Control inputs, exact-SHA independent review and external
# Environment protection/approval remain required. This list cannot grant
# private transfer permission or relax an Environment branch restriction.
# PR234 is only the bounded B S11 dependency/schema recipe. Same private
# Control blobs/credential scope, final-SHA review and Environment protections.
# It grants no Application-Source fetch, Host action or generic PR admission.
# PR235 is only the native Mac PG17 B-admission Source/metadata-reader profile.
# Same three pinned Control blobs, actual-SHA independent review and required
# Environment approval; no productive DSN/data, Host action or generic PR gate.
APPROVED_SOURCE_PRS=frozenset((225,226,227,228,229,230,231,232,233,234,235))
NATIVE_TESTS=64
MAX_OUTPUT=16*1024*1024
CAPSULE_SHA='11b8434626553e832cdcc43590867a8044025d8d16799d4d10ad4311cf1e33bb'
PUBLIC_ERRORS=frozenset('CONTROL_RECOVERY_'+name for name in (
    'CI_PLATFORM_BINDING_RED','CI_EVENT_RED','CI_UNTRUSTED_PR_RED','CI_PUSH_REF_RED',
    'CI_SOURCE_SHA_RED','CI_SOURCE_WORKING_SET_RED','CI_CHILD_TIMEOUT','CI_OUTPUT_BOUND','CI_PRIVATE_COMMAND_RED',
    'CI_PRIVATE_LOCATION_RED','CI_CLEANUP_TARGET_RED','CI_CLEANUP_RED','CI_CAPSULE_BINDING_RED',
    'CI_FOREIGN_CONTAINER_RED','CI_CONTAINER_CLEANUP_RED',
    'CI_READ_CREDENTIAL_MISSING_OR_WRONG_KIND','CI_NATIVE_RED'))


def runtime_binding(env,root):
    c.require(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_REPOSITORY')==REPOSITORY and
              env.get('CONTROL_PRIVATE_ENVIRONMENT')==ENVIRONMENT,'CI_PLATFORM_BINDING_RED')
    event=env.get('GITHUB_EVENT_NAME')
    c.require(event in ('pull_request','push'),'CI_EVENT_RED')
    value=json.loads(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    if event=='pull_request':
        c.require(value['pull_request']['head']['repo']['full_name']==REPOSITORY and
                  type(value['number']) is int and value['number'] in APPROVED_SOURCE_PRS,
                  'CI_UNTRUSTED_PR_RED')
        expected=value['pull_request']['head']['sha']
    else:
        c.require(value['ref']=='refs/heads/control-main','CI_PUSH_REF_RED')
        expected=value['after']
    c.require(re.fullmatch('[a-f0-9]{40}',expected or '') and expected==env.get('EXPECTED_SOURCE_SHA'),
              'CI_SOURCE_SHA_RED')
    git=['/usr/bin/git','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(root)]
    code=subprocess.run(git+['rev-parse','HEAD'],
                        env=tool_env(),capture_output=True,timeout=10)
    c.require(code.returncode==0 and code.stdout.decode().strip()==expected,'CI_SOURCE_SHA_RED')
    for args in (('status','--porcelain=v1','--untracked-files=all'),
                 ('ls-files','--others','--ignored','--exclude-standard','-z')):
        state=subprocess.run(git+list(args),env=tool_env(),capture_output=True,timeout=10)
        c.require(state.returncode==0 and not state.stdout,'CI_SOURCE_WORKING_SET_RED')
    return expected


def tool_env():
    # No inherited token, Git tracing/config includes, Docker context or helper.
    return {'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_GLOBAL':'/dev/null',
            'GIT_CONFIG_SYSTEM':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0',
            'PYTHONDONTWRITEBYTECODE':'1','DOCKER_HOST':'unix:///var/run/docker.sock'}


def bounded(argv,*,env=None,cwd=None,timeout=120):
    """Captured bytes are private memory, never exception repr/public stdout."""
    child=subprocess.Popen(argv,cwd=cwd,env=tool_env() if env is None else env,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    data=bytearray();selector=selectors.DefaultSelector();deadline=time.monotonic()+timeout
    try:
        for stream in (child.stdout,child.stderr):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
        while selector.get_map():
            remaining=deadline-time.monotonic();c.require(remaining>0,'CI_CHILD_TIMEOUT')
            c.require(selector.select(remaining),'CI_CHILD_TIMEOUT')
            for key,_ in selector.select(0):
                chunk=os.read(key.fd,65536)
                if not chunk:selector.unregister(key.fileobj);continue
                c.require(len(data)+len(chunk)<=MAX_OUTPUT,'CI_OUTPUT_BOUND')
                data.extend(chunk)
        return child.wait(timeout=max(0.01,deadline-time.monotonic())),bytes(data)
    finally:
        # Descendants may hold pipes after the leader exits. Its newly created
        # session/group remains OUR group; never just test leader.poll().
        try:
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:child.wait(timeout=1)
            except subprocess.TimeoutExpired:pass
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=5)
        finally:
            selector.close()
            for stream in (child.stdout,child.stderr):stream.close()


def require_command(argv,**kwargs):
    code,raw=bounded(argv,**kwargs);c.require(code==0,'CI_PRIVATE_COMMAND_RED');return raw


def private_root(parent,workspace):
    parent=Path(parent)
    c.require(parent.is_dir() and not parent.is_symlink() and parent.resolve()==parent and
              not parent.is_relative_to(workspace) and not workspace.is_relative_to(parent),
              'CI_PRIVATE_LOCATION_RED')
    return Path(tempfile.mkdtemp(prefix='tu1nz-control-private-',dir=parent))


def remove_private(root,parent):
    # Only the freshly owned finite mkdtemp child, never arbitrary input/root.
    c.require(root.parent==parent and root.name.startswith('tu1nz-control-private-') and
              not root.is_symlink() and root.is_dir() and root.stat().st_uid==os.geteuid(),
              'CI_CLEANUP_TARGET_RED')
    shutil.rmtree(root)
    c.require(not os.path.lexists(root),'CI_CLEANUP_RED')


def fetch_capsule(private,token):
    source=private/'source.git';source.mkdir(mode=0o700)
    ask=private/'askpass.py'
    save_new(ask,b'#!/usr/bin/python3\nimport os,sys\nprint("x-access-token" if "Username" in sys.argv[1] else os.environ["CONTROL_POLICY_READ_TOKEN"])\n')
    ask.chmod(0o700)
    fetch_env={**tool_env(),'GIT_ASKPASS':str(ask),'CONTROL_POLICY_READ_TOKEN':token}
    git=['/usr/bin/git','--no-optional-locks','-C',str(source),'-c','core.hooksPath=/dev/null']
    try:
        require_command(git+['init','--bare','-q'],env=tool_env())
        require_command(git+['remote','add','origin',c.TARGET['repository']],env=tool_env())
        # Only exact target and its required ancestry, no arbitrary branches.
        require_command(git+['fetch','--no-tags','origin',c.TARGET['commit']],env=fetch_env,timeout=180)
    finally:
        fetch_env.pop('CONTROL_POLICY_READ_TOKEN',None)
        ask.unlink(missing_ok=True)
    raw=build_capsule(source)
    c.require(c.digest(raw)==CAPSULE_SHA,'CI_CAPSULE_BINDING_RED')
    capsule=private/'target-capsule.json';save_new(capsule,raw)
    # The native process sees only the authenticated capsule, not bare Git.
    shutil.rmtree(source)
    return capsule,c.digest(raw)


def native_argv(workspace,capsule,image,name,owner):
    return ['/usr/bin/docker','run','--name',name,'--label','tu1nz.private-ci.owner='+owner,
        '--network','none','--privileged','--env','container=docker',
        '--env','TU1NZ_CONTROL_POLICY_CAPSULE=/target-capsule.json',
        '--mount','type=bind,src='+str(workspace)+',dst=/work,readonly',
        '--mount','type=bind,src='+str(capsule)+',dst=/target-capsule.json,readonly',
        '--workdir','/work',image,'bash','tests/control_only_recovery_native.sh']


def cleanup_container(name,owner):
    raw=require_command(['/usr/bin/docker','container','ls','--all','--filter','name=^/'+name+'$',
                         '--format','{{.ID}}'],timeout=15)
    if not raw.strip():return
    raw=require_command(['/usr/bin/docker','inspect',name],timeout=15)
    value=json.loads(raw)[0]
    c.require(value['Config']['Labels'].get('tu1nz.private-ci.owner')==owner,'CI_FOREIGN_CONTAINER_RED')
    require_command(['/usr/bin/docker','rm','--force','--volumes',name],timeout=30)
    raw=require_command(['/usr/bin/docker','container','ls','--all','--filter','name=^/'+name+'$',
                         '--format','{{.ID}}'],timeout=10)
    c.require(not raw.strip(),'CI_CONTAINER_CLEANUP_RED')


@contextlib.contextmanager
def interrupted():
    def stop(signum,frame):raise InterruptedError('private CI interrupted')
    previous={s:signal.signal(s,stop) for s in (signal.SIGTERM,signal.SIGINT)}
    try:yield
    finally:
        for s,handler in previous.items():signal.signal(s,handler)


def run(workspace,image):
    root=None;container=None;owner=uuid.uuid4().hex;result={'green':False,'code':'CONTROL_PRIVATE_CI_RED'}
    parent=Path(os.environ.get('RUNNER_TEMP','/nonexistent'))
    try:
        token=os.environ.pop('CONTROL_POLICY_READ_TOKEN',None)
        runtime_binding(os.environ,workspace)
        c.require(type(token) is str and token.startswith('github_pat_'),'CI_READ_CREDENTIAL_MISSING_OR_WRONG_KIND')
        root=private_root(parent,workspace)
        capsule,capsule_sha=fetch_capsule(root,token);token=None
        container='tu1nz-control-private-'+owner
        code,output=bounded(native_argv(workspace,capsule,image,container,owner),timeout=180)
        c.require(code==0 and re.search(rb'Ran '+str(NATIVE_TESTS).encode()+rb' tests in [0-9.]+s',output) and
                  output.rstrip().endswith(b'OK') and b'skipped' not in output,'CI_NATIVE_RED')
        result={'green':True,'code':'CONTROL_PRIVATE_CI_GREEN','tests':NATIVE_TESTS,'capsule_sha256':capsule_sha}
    except BaseException as error:
        # No arbitrary exception string, traceback, command or child output.
        code=str(error)
        result={'green':False,'code':code if isinstance(error,c.RecoveryError) and code in PUBLIC_ERRORS
                else 'CONTROL_PRIVATE_CI_RED'}
    finally:
        try:
            if container is not None:cleanup_container(container,owner)
        except BaseException:result={'green':False,'code':'CONTROL_PRIVATE_CONTAINER_CLEANUP_RED'}
        try:
            if root is not None:remove_private(root,parent)
        except BaseException:result={'green':False,'code':'CONTROL_PRIVATE_INPUT_CLEANUP_RED'}
    print(json.dumps(result,sort_keys=True))
    return 0 if result['green'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);args=parser.parse_args()
    workspace=Path(__file__).resolve().parents[1]
    with interrupted():raise SystemExit(run(workspace,args.image))
