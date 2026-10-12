"""Exact source-only annotated freeze. No force, Host authority or key access."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_control_recovery_contract as c
from tu1nz_control_recovery_entry import MODULES,PUBLIC_SHA

TAG='control-only-recovery-source-freeze-r1'
REPO='Tausendunde1nz/infra'
ROOT=Path(__file__).resolve().parents[1]
FILES=[*(f'scripts/{name}.py' for name in MODULES),
 'scripts/tu1nz_control_recovery_authority.py','scripts/tu1nz_control_recovery_release.py',
 'scripts/tu1nz_control_recovery_freeze.py','tests/test_control_only_recovery.py',
 'tests/control_recovery_scenarios.py','tests/control_only_recovery_native.sh',
 'docs/CONTROL_ONLY_RECOVERY_R1.md','docs/CONTROL_ONLY_RECOVERY_R1_LIVE_PLAN.txt',
 'docs/CONTROL_ONLY_RECOVERY_SHARED_HANDOFF.txt','manifests/control-only-recovery-r1.json',
 'config/control-only-recovery/authority-ed25519.pub','.github/workflows/control-validation.yml','.gitignore']


def command(argv):
    value=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=45)
    c.require(value.returncode==0,'FREEZE_COMMAND_RED');return value.stdout


def git(*argv):return command(['/usr/bin/git','--no-optional-locks',*argv])
def api(path):return json.loads(command(['gh','api',path]))


def gates(pr,head,pr_run,merge_run,review_comment):
    c.require(re.fullmatch('[0-9a-f]{40}',head),'REVIEW_HEAD_RED')
    pull=api(f'repos/{REPO}/pulls/{pr}')
    merge=git('rev-parse','HEAD').decode().strip();tree=git('rev-parse','HEAD^{tree}').decode().strip()
    c.require(pull['merged'] and pull['head']['sha']==head and pull['merge_commit_sha']==merge,
              'FREEZE_PR_BINDING_RED')
    c.require(git('rev-parse',head+'^{tree}').decode().strip()==tree,'MERGE_TREE_DRIFT')
    c.require(git('symbolic-ref','--short','HEAD').decode().strip()=='control-main' and
        not git('status','--porcelain=v1') and
        git('ls-remote','origin','refs/heads/control-main').decode().split()[0]==merge,'CANONICAL_MERGE_RED')
    ci=[]
    for run_id,sha,event in ((pr_run,head,'pull_request'),(merge_run,merge,'push')):
        run=api(f'repos/{REPO}/actions/runs/{run_id}')
        c.require(run['head_sha']==sha and run['event']==event and run['status']=='completed' and
            run['conclusion']=='success' and run['path']=='.github/workflows/control-validation.yml','CI_GATE_RED')
        jobs=api(f'repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100')['jobs']
        job=next(v for v in jobs if v['name']=='restore-contract')
        required=('S8 durable anchor','Control-only create-only recovery','R15 aborted containment',
                  'S11/S12 release compatibility','R12 native Linux','Integrated S12 attempt chain')
        for prefix in required:
            c.require(any(s['name'].startswith(prefix) and s['conclusion']=='success' for s in job['steps']),
                      'NATIVE_GATE_MISSING')
        c.require(job['conclusion']=='success','CI_GATE_RED')
        ci.append({'id':run_id,'sha':sha,'url':run['html_url'],'conclusion':'success'})
    review=api(f'repos/{REPO}/issues/comments/{review_comment}')
    reviewed=re.search(r'Reviewed commit:\*\* `([0-9a-f]{10,40})`',review['body'])
    c.require(review['user']['login']=='chatgpt-codex-connector[bot]' and reviewed is not None and
        head.startswith(reviewed[1]) and "Didn't find any major issues" in review['body'] and
        review['issue_url'].endswith('/issues/'+str(pr)),'SAME_SHA_REVIEW_RED')
    query='query {repository(owner:"Tausendunde1nz",name:"infra"){pullRequest(number:'+str(pr)+')'+\
        '{reviewThreads(first:100){pageInfo{hasNextPage} nodes{isResolved comments(first:100){nodes{body}}}}}}}'
    threads=json.loads(command(['gh','api','graphql','-f','query='+query]))['data']['repository']['pullRequest']['reviewThreads']
    c.require(not threads['pageInfo']['hasNextPage'] and not any(not t['isResolved'] and any(
        re.search(r'\bP[12]\b',m['body']) for m in t['comments']['nodes']) for t in threads['nodes']),
        'OPEN_REVIEW_FINDING')
    return merge,tree,ci,{'head':head,'url':review['html_url'],'comment_id':review_comment,'findings':'NONE'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--pr',type=int,required=True)
    parser.add_argument('--head',required=True);parser.add_argument('--pr-run',type=int,required=True)
    parser.add_argument('--merge-run',type=int,required=True);parser.add_argument('--review-comment',type=int,required=True)
    parser.add_argument('--publish',action='store_true');args=parser.parse_args()
    merge,tree,ci,review=gates(args.pr,args.head,args.pr_run,args.merge_run,args.review_comment)
    # Absence BOTH sides before creating. Never force/overwrite an old tag.
    tags=git('tag','--list',TAG);remote=git('ls-remote','origin','refs/tags/'+TAG,'refs/tags/'+TAG+'^{}')
    c.require(not tags and not remote,'FREEZE_ALREADY_EXISTS_NO_REPLACEMENT')
    manifest=json.loads(git('show',merge+':manifests/control-only-recovery-r1.json'))
    c.require(manifest['target']==c.TARGET and manifest['public_key_sha256']==PUBLIC_SHA and
        manifest['live_authority'] is False and git('rev-parse',manifest['r6_tag']).decode().strip()==
        manifest['r6_tag_object'],'RELEASE_BINDING_RED')
    hashes={name:c.digest(git('show',merge+':'+name)) for name in FILES}
    value={'schema':c.SCHEMA+'_SOURCE_FREEZE','tag':TAG,'control':{'commit':merge,'tree':tree},
        'pr':args.pr,'review':review,'ci':ci,'files':hashes,'release':manifest,
        'source_only':True,'host_calls':0,'deployment_authority':False}
    raw=c.canonical(value)
    subprocess.run(['/usr/bin/git','tag','-a',TAG,merge,'-F','-'],cwd=ROOT,input=raw+b'\n',check=True)
    tag=git('rev-parse',TAG).decode().strip()
    c.require(git('cat-file','tag',TAG).partition(b'\n\n')[2].rstrip(b'\n')==raw,'LOCAL_FREEZE_READBACK_RED')
    if args.publish:
        git('push','origin','refs/tags/'+TAG)
        expected={tag:'refs/tags/'+TAG,merge:'refs/tags/'+TAG+'^{}'}
        observed={row.split()[0]:row.split()[1] for row in git('ls-remote','origin',
            'refs/tags/'+TAG,'refs/tags/'+TAG+'^{}').decode().splitlines()}
        c.require(observed==expected,'REMOTE_FREEZE_READBACK_RED')
    print(json.dumps({'tag':TAG,'tag_object':tag,'commit':merge,'tree':tree,'payload_sha256':c.digest(raw),
                      'remote_verified':args.publish,'live_authority':False}))


if __name__=='__main__':main()
