"""Trusted-client, fixed-slot admission. Never run this on the recovery host.

The signing key and BOTH spent records stay on the approved operator's Mac,
outside the host repository-writer namespace. Before any SSH dispatch the
client spends SLOT; absent host paths/new releases NEVER reset it. Only one
signed grant for the exact live PID/boot/nonce can follow that dispatch.
No restoration of these records, key rotation or new slot is automatic.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import selectors
import time
import sys

import tu1nz_control_recovery_contract as c

CLIENT_ROOT=Path('/Users/daniel/Developer/tu1nz/control-only-recovery-authority')
CLIENT_MIRROR=Path('/Users/daniel/.codex/backups/control-only-recovery-authority')
CLIENT_OPENSSL='/opt/homebrew/bin/openssl' if sys.platform=='darwin' else '/usr/bin/openssl'
MARKER_SUFFIXES=('attempt','signature-reserved','grant-body','grant','result','accepted','revoked')


def fsync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def new(path,raw):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o400)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fsync_directory(path.parent)


def secure_client_parent(path):
    st=path.lstat()
    c.require(stat.S_ISDIR(st.st_mode) and not path.is_symlink() and st.st_uid==os.geteuid()
              and not stat.S_IMODE(st.st_mode)&0o077,'CLIENT_AUTHORITY_DIRECTORY_RED')


def spend_before_dispatch(root=CLIENT_ROOT,mirror=CLIENT_MIRROR,*,release):
    """Fail closed on either missing/mismatched/partial existing copy; never heal."""
    for p in (root,mirror):secure_client_parent(p)
    paths=[p/(c.SLOT+'.attempt.json') for p in (root,mirror)]
    c.require(not any(os.path.lexists(parent/(c.SLOT+'.'+suffix+'.json'))
        for parent in (root,mirror) for suffix in MARKER_SUFFIXES),
        'CLIENT_SLOT_ALREADY_OR_AMBIGUOUSLY_CONSUMED')
    raw=c.canonical({'schema':c.SCHEMA+'_CLIENT_ATTEMPT','slot':c.SLOT,'release':release,
                     'automatic_retry':False,'signature_dispatched':False})
    for path in paths:new(path,raw)
    for path in paths:c.require(path.read_bytes()==raw,'CLIENT_ATTEMPT_READBACK_RED')
    return raw


def sign_for_dispatched_session(body,key,root=CLIENT_ROOT,mirror=CLIENT_MIRROR,*,openssl=CLIENT_OPENSSL,target=None):
    target=c.TARGET if target is None else target
    paths=[p/(c.SLOT+'.attempt.json') for p in (root,mirror)]
    attempts=[p.read_bytes() for p in paths]
    c.require(attempts[0]==attempts[1] and json.loads(attempts[0])['slot']==c.SLOT,'CLIENT_ATTEMPT_BINDING_RED')
    c.require(body['schema']==c.SCHEMA+'_GRANT' and body['slot']==c.SLOT and body['target']==target
              and len(body['nonce'])==64 and body['pid']>0,'CLIENT_SESSION_BINDING_RED')
    if target==c.TARGET:
        release=json.loads(attempts[0])['release']
        c.require(body['host']==c.MACHINE and body['historical_root']==list(c.R6_ROOT) and
            body['historical_guard']==list(c.R6_GUARD) and body['quarantined_git']==list(c.R6_QUARANTINE)
            and body['capsule_sha256']==release['capsule_sha256'] and
            body['governance']['source_release']==release['source_release'] and
            c.digest(c.canonical(body['governance']))==release['governance_intent_sha256'],
            'CLIENT_PRODUCTION_BINDING_RED')
    reservations=[p/(c.SLOT+'.signature-reserved.json') for p in (root,mirror)]
    c.require(not any(os.path.lexists(p) for p in reservations),'SIGNATURE_ALREADY_OR_AMBIGUOUSLY_CONSUMED')
    reservation=c.canonical({'schema':c.SCHEMA+'_CLIENT_SIGNATURE_RESERVED','slot':c.SLOT,
        'body_sha256':c.digest(c.canonical(body)),'attempt_sha256':c.digest(attempts[0])})
    for path in reservations:new(path,reservation)
    # Reserve BEFORE key access or signing: an exception cannot allow another
    # signature, session, host restart or corrected source run.
    st=key.lstat()
    c.require(stat.S_ISREG(st.st_mode) and not key.is_symlink() and st.st_uid==os.geteuid()
              and not stat.S_IMODE(st.st_mode)&0o177,'CLIENT_KEY_RED')
    body_raw=c.canonical(body)
    for p in (root,mirror):new(p/(c.SLOT+'.grant-body.json'),body_raw)
    body_path=root/(c.SLOT+'.grant-body.json')
    result=subprocess.run([openssl,'pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(body_path)],
        capture_output=True,timeout=10,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
    for p in (root,mirror):c.require((p/(c.SLOT+'.grant-body.json')).read_bytes()==body_raw,'CLIENT_BODY_CHANGED')
    c.require(result.returncode==0 and len(result.stdout)==64,'CLIENT_SIGNATURE_RED')
    grant={'body':body,'signature':base64.b64encode(result.stdout).decode()}
    raw=c.canonical(grant)
    for p in (root,mirror):new(p/(c.SLOT+'.grant.json'),raw)
    for p in (root,mirror):c.require((p/(c.SLOT+'.grant.json')).read_bytes()==raw,'CLIENT_GRANT_READBACK_RED')
    return grant


def supervise_single_dispatch(dispatch,root=CLIENT_ROOT,mirror=CLIENT_MIRROR,*,release):
    """Exactly one call, no exception/reply/status can cause redispatch.

    The transport must already have verified the complete frozen source and
    artifact, and use the approved SSH identity/command-only sudo. Tests inject
    a synthetic callable; this module has no network or SSH implementation.
    """
    attempt=spend_before_dispatch(root,mirror,release=release)
    try:return dispatch(c.digest(attempt))
    except BaseException:
        raise  # spent records remain; not a reset or retry policy


def accept_final(result,grant,root=CLIENT_ROOT,mirror=CLIENT_MIRROR):
    """Only a received final result, never an orphaned host receipt, accepts.

    No host action here. Consumers must check BOTH acceptance records and
    absence of either revocation. Partial persistence remains locked UNKNOWN.
    """
    c.require(result.get('schema')==c.SCHEMA+'_RESULT' and result.get('accepted') is True and
        result.get('primary') is None and result.get('abort') is None and result.get('cleanup')==[] and
        result.get('fd_baseline_restored') is True and result.get('fd_limit_restored') is True and
        result.get('historical_mutated') is False and result.get('consumer_activation') is False,
        'FINAL_CLIENT_ACCEPTANCE_RED')
    raw_grant=c.canonical(grant)
    receipt=result['receipt']
    c.require(receipt['grant_sha256']==c.digest(raw_grant) and receipt['slot']==c.SLOT and
        receipt['host']==grant['body']['host'] and receipt['target']==grant['body']['target'] and
        receipt['capsule_sha256']==grant['body']['capsule_sha256'],'CLIENT_RESULT_BINDING_RED')
    if grant['body'].get('governance') is not None:
        c.require(receipt['governance']['intent_sha256']==c.digest(c.canonical(grant['body']['governance'])) and
                  receipt['governance']['transaction_sha256']==c.digest(c.canonical(grant['body'])),
                  'CLIENT_GOVERNANCE_BINDING_RED')
    for parent in (root,mirror):
        secure_client_parent(parent)
        c.require((parent/(c.SLOT+'.grant.json')).read_bytes()==raw_grant,'CLIENT_GRANT_READBACK_RED')
        c.require(not os.path.lexists(parent/(c.SLOT+'.revoked.json')),'CLIENT_VIEW_REVOKED')
    raw=c.canonical({'schema':c.SCHEMA+'_CLIENT_ACCEPTED','slot':c.SLOT,
        'grant_sha256':c.digest(raw_grant),'result_sha256':c.digest(c.canonical(result)),
        'prepared_sha256':c.digest(c.canonical(result['receipt'])),
        'target':grant['body']['target'],'host':grant['body']['host'],'deployment_authority':False})
    for parent in (root,mirror):new(parent/(c.SLOT+'.accepted.json'),raw)
    c.require(read_acceptance(root,mirror)==json.loads(raw),'CLIENT_ACCEPTANCE_READBACK_RED')
    return json.loads(raw)


def read_acceptance(root=CLIENT_ROOT,mirror=CLIENT_MIRROR):
    for parent in (root,mirror):
        secure_client_parent(parent)
        c.require(not os.path.lexists(parent/(c.SLOT+'.revoked.json')),'CLIENT_VIEW_REVOKED')
    records=[(p/(c.SLOT+'.accepted.json')).read_bytes() for p in (root,mirror)]
    c.require(records[0]==records[1],'CLIENT_ACCEPTANCE_AMBIGUOUS')
    value=json.loads(records[0]);c.require(value['schema']==c.SCHEMA+'_CLIENT_ACCEPTED' and
        value['slot']==c.SLOT and value['deployment_authority'] is False,'CLIENT_ACCEPTANCE_AMBIGUOUS')
    return value


def revoke_acceptance(root=CLIENT_ROOT,mirror=CLIENT_MIRROR):
    """The finite rollback: withdraw view eligibility, retain every byte/guard.

    A failed/partial revocation still denies via EITHER marker; no cleanup,
    historical restoration, retry, consumer stop or automatic reset follows.
    """
    value=read_acceptance(root,mirror)
    raw=c.canonical({'schema':c.SCHEMA+'_CLIENT_REVOKED','slot':c.SLOT,
                     'acceptance_sha256':c.digest(c.canonical(value)),'retry_allowed':False})
    for parent in (root,mirror):new(parent/(c.SLOT+'.revoked.json'),raw)
    for parent in (root,mirror):c.require((parent/(c.SLOT+'.revoked.json')).read_bytes()==raw,
                                        'CLIENT_REVOCATION_READBACK_RED')
    return {'view_eligible':False,'historical_restored':False,'host_mutated':False,'retry_allowed':False}


def transport_once(factory,packet,key,root=CLIENT_ROOT,mirror=CLIENT_MIRROR,*,release,
                   password=None,openssl=CLIENT_OPENSSL):
    """One owned pipe transport; factory is the approved exact SSH argv only.

    Caller verifies freeze/packet, CURRENT protected Host gates and live
    authority before entering. This function cannot invent that authority.
    No generic CLI or automatic execution is exposed. Tests use a synthetic
    pipe peer. No password, raw stderr, private key or user data is recorded.
    """
    c.require(release['packet_sha256']==c.digest(packet),'TRANSPORT_PACKET_RED')
    # Explicit protected Host prerequisite record, not Source-test GREEN.
    c.require(release.get('host_gates')=={
        'protected_current_read':'GREEN','tools_kernel_tcb':'GREEN','writer_device_boundary':'GREEN',
        'capacity_filesystem':'GREEN','public_and_consumer_baseline':'GREEN',
        'authenticated_isolated_bootstrap_intent':'GREEN',
        'exact_host_scope_authorized':'GREEN'},'HOST_GATES_OPEN')
    # Caller independently authenticates the Source freeze and current Host
    # permission. Never consume the fixed slot for a stale packet or policy.
    from tu1nz_control_recovery_entry import executor_digest,PUBLIC_SHA
    from tu1nz_control_recovery_governance import prepare,intent,validate_source
    value=json.loads(packet);source=release['source_release'];validate_source(source)
    c.require(set(value)=={'schema','modules','source','public','capsule'} and
        value['schema']==c.SCHEMA+'_MEMORY_PACKET' and value['source']==source and
        executor_digest(value['modules'])==source['executor_sha256'] and
        c.digest(base64.b64decode(value['public'],validate=True))==PUBLIC_SHA,'TRANSPORT_SOURCE_RED')
    capsule=c.Capsule(base64.b64decode(value['capsule'],validate=True))
    plan=prepare(capsule,c.Layout.production(),source)
    c.require(capsule.sha256==release['capsule_sha256'] and
        c.digest(c.canonical(intent(plan)))==release['governance_intent_sha256'],'TRANSPORT_BOOTSTRAP_RED')
    proc=None;selector=None;out={'schema':c.SCHEMA+'_TRANSPORT_RESULT','accepted':False,
        'primary':None,'abort':None,'cleanup':[],'automatic_retry':False,'host_outcome':'UNKNOWN'}
    def dispatch(_):
        nonlocal proc,selector
        proc=factory();c.require(proc.stdin is not None and proc.stdout is not None,'TRANSPORT_PIPES_RED')
        # Time starts BEFORE packet upload/HELLO, not again for each read.
        deadline=time.monotonic()+50;selector=selectors.DefaultSelector()
        selector.register(proc.stdout,selectors.EVENT_READ)
        payload=(password+b'\n' if password is not None else b'')+packet+b'\n'
        # A single bounded whole-packet write with a nonblocking own pipe.
        os.set_blocking(proc.stdin.fileno(),False)
        offset=0
        while offset<len(payload):
            c.require(time.monotonic()<deadline,'TRANSPORT_TIMEOUT')
            try:offset+=os.write(proc.stdin.fileno(),payload[offset:offset+65536])
            except BlockingIOError:time.sleep(0.01)
        buffered=bytearray()
        def line():
            while b'\n' not in buffered:
                remain=deadline-time.monotonic();c.require(remain>0,'TRANSPORT_TIMEOUT')
                c.require(selector.select(remain),'TRANSPORT_TIMEOUT')
                chunk=os.read(proc.stdout.fileno(),65536)
                c.require(chunk and len(buffered)+len(chunk)<=4*1024*1024,'TRANSPORT_OUTPUT_RED')
                buffered.extend(chunk)
            first,_,rest=buffered.partition(b'\n');buffered[:]=rest
            return json.loads(first)
        hello=line();c.require(hello['schema']==c.SCHEMA+'_HELLO','TRANSPORT_HELLO_RED')
        grant=sign_for_dispatched_session(hello['body'],key,root,mirror,openssl=openssl)
        raw=c.canonical(grant)+b'\n'
        offset=0
        while offset<len(raw):
            c.require(time.monotonic()<deadline,'TRANSPORT_TIMEOUT')
            try:offset+=os.write(proc.stdin.fileno(),raw[offset:])
            except BlockingIOError:time.sleep(0.01)
        proc.stdin.close();result=line()
        code=proc.wait(timeout=max(0.001,deadline-time.monotonic()))
        c.require(code==0 and not buffered,'TRANSPORT_FINAL_EXIT_RED')
        # Persist raw datensparse result before acceptance; a persistence or
        # pipe-close error cannot leave a client acceptance record behind.
        for parent in (root,mirror):new(parent/(c.SLOT+'.result.json'),c.canonical(result))
        proc.stdout.close();selector.close();selector=None
        return accept_final(result,grant,root,mirror)
    try:
        out['acceptance']=supervise_single_dispatch(dispatch,root,mirror,release=release)
        out['accepted']=True;out['host_outcome']='NEW_VIEW_PREPARED_NO_DEPLOYMENT'
    except BaseException as error:out['primary']=c.failure(error)
    finally:
        if selector is not None:
            try:selector.close()
            except BaseException as error:out['cleanup'].append(c.failure(error))
        if proc is not None:
            # ONLY this factory-created transport process, never server/other
            # processes. Remote GNU timeout independently bounds the executor.
            try:
                if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
            except BaseException as error:out['abort']=c.failure(error)
            for stream in (proc.stdin,proc.stdout):
                try:
                    if stream is not None and not stream.closed:stream.close()
                except BaseException as error:out['cleanup'].append(c.failure(error))
    if out['abort'] or out['cleanup']:out['accepted']=False
    return out
