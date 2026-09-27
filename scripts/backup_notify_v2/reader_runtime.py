"""Bundled runtime: only fixed archived inputs and fixed Bash parse-only child."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys

PREFIX='TU1NZ_BACKUP_NOTIFY_V2='


def guarded(path,expected,limit=2_000_000,private=True):
    for p in reversed(path.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('ancestor')
        if any('posix_acl' in x for x in os.listxattr(p)):raise ValueError('ancestor_acl')
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&(0o077 if private else 0o022):raise ValueError('file_identity')
    if any('posix_acl' in x for x in os.listxattr(path)):raise ValueError('file_acl')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno());data=f.read(limit+1);after=os.fstat(f.fileno())
    fields=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if fields(s)!=fields(before) or fields(before)!=fields(after) or len(data)>limit:raise ValueError('file_drift')
    if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('hash_mismatch')
    return data


def _expired(signum,frame):raise TimeoutError('reader_deadline')


def unit_state(name,binding):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service',name):raise ValueError('unit_name')
    guarded(Path('/usr/bin/systemctl'),binding['systemctl_sha256'],16_000_000,private=False)
    command=['/usr/bin/systemctl','show','--no-pager','-p','User','-p','ActiveState','-p','UnitFileState','-p','LoadState','-p','DropInPaths','--',name]
    r=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     timeout=5,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/')
    if r.returncode or r.stderr or len(r.stdout)>16384:raise ValueError('unit_state')
    return dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)


def main(binding,engine,parser):
    if os.geteuid()!=0 or len(sys.argv)!=1:return 77
    os.environ.clear();os.environ.update({'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_CPU,(45,45))
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    signal.signal(signal.SIGALRM,_expired);signal.alarm(60)
    result={'version':'2.0.0','classification':'REVIEW_REQUIRED','activation_ready':False,'callers':[]}
    try:
        guarded(Path('/usr/bin/bash'),binding['bash_sha256'],limit=16_000_000,private=False)
        root=Path(binding['archive_root'])
        source=guarded(root/binding['source_archive'],binding['source_sha256'])
        # Suppress parser diagnostics, which might otherwise include source literals.
        with contextlib.redirect_stderr(io.StringIO()),contextlib.redirect_stdout(io.StringIO()):
            result['syntax_and_env']=engine.analyse(source,parser)
        coverage=result['syntax_and_env'].get('previous_error_coverage',{})
        if result['syntax_and_env'].get('status')=='PARSED_COMPLETE' and not all(coverage.get(str(n),{}).get('ast_kinds') for n in (22,23,29)):
            result['syntax_and_env']['status']='INCOMPLETE_ERROR_SITE_COVERAGE'
        if result['syntax_and_env'].get('status')=='PARSED_COMPLETE' and not all(coverage.get(str(n),{}).get('legacy_line_lexer_error') for n in (22,23,29)):
            result['syntax_and_env']['status']='INCOMPLETE_LEGACY_ERROR_REPRODUCTION'
        result['bash_sha256']=binding['bash_sha256']
        result['source_sha256']=binding['source_sha256']
        total=0;checked=0;unresolved=0;direct_hits=0
        for candidate in binding['callers']:
            raw=guarded(root/candidate['archive'],candidate['sha256'])
            checked+=1;total+=len(raw)
            if total>64*1024*1024:raise ValueError('caller_byte_budget')
            if b'backup_notify.sh' not in raw:continue
            if candidate['path']=='/usr/local/bin/backup_notify.sh':continue
            direct_hits+=1
            row={'path':candidate['path'],'sha256':candidate['sha256'],'archive':candidate['archive'],
                 'category':candidate['category'],'active':'UNVERIFIED','root':'UNVERIFIED'}
            if b'\x00' in raw:row['status']='BINARY_TEXT_HIT';unresolved+=1
            else:
                try:
                    with contextlib.redirect_stderr(io.StringIO()),contextlib.redirect_stdout(io.StringIO()):
                        row.update(engine.caller_fragments(raw,candidate['path'],parser))
                    live=Path(candidate['path'])
                    guarded(live,candidate['sha256'],private=False)
                    row['hash_matches']=True
                    row['semantic_call']=any(f['calls'] for f in row.get('fragments',[]))
                    contexts={f['context'] for f in row.get('fragments',[])}
                    if 'CRON' in contexts:
                        row['root']=any(f.get('root') is True and f['calls'] for f in row['fragments'])
                        state=unit_state('cron.service',binding)
                        row['active']=state.get('ActiveState')=='active'
                        if candidate['path'].startswith('/etc/cron.d/') and not re.fullmatch(r'[A-Za-z0-9_-]+',live.name):row['active']='UNVERIFIED_FILENAME_POLICY'
                        row['activation_unit']='cron.service'
                    elif 'SYSTEMD' in contexts:
                        name=live.name if live.suffix=='.service' else live.parent.name[:-2]
                        state=unit_state(name,binding)
                        row['root']=state.get('User') in ('','root','0') or any(f.get('force_root') for f in row['fragments'])
                        row['active']=state.get('ActiveState')=='active'
                        row['activation_unit']=name
                        row['unit_state']={k:state.get(k) for k in ('LoadState','ActiveState','UnitFileState')}
                        row['additional_dropins_present']=bool(state.get('DropInPaths'))
                        if state.get('DropInPaths'):row['root']='UNVERIFIED';row['active']='UNVERIFIED'
                except Exception as e:row.update(status='CALLER_PARSE_OR_STATE_INCOMPLETE',error_class=type(e).__name__);unresolved+=1
            row['resolution_closed']=row.get('status')=='PARSED' and type(row.get('root')) is bool and type(row.get('active')) is bool
            result['callers'].append(row)
        result['caller_scan']={'fixed_candidates_checked':checked,'bytes':total,'literal_hits':direct_hits,
            'coverage_closed':False,'dynamic_caller_absence_proved':False,'unresolved_hits':unresolved}
        result['status']='COLLECTED'
        result['classification']=engine.caller_decision(result['syntax_and_env'],result['callers'],coverage_closed=False)
    except Exception as e:
        result.update(status='INCOMPLETE',error_class=type(e).__name__)
    finally:signal.alarm(0)
    print(PREFIX+json.dumps(result,sort_keys=True))
    return 0 if result['status']=='COLLECTED' else 2
