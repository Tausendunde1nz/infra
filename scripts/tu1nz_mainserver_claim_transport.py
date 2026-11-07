"""Locally reviewed, finite SSH transport for the R4 early metadata reader.

Run only in a visible local terminal. A password is read personally via getpass,
never accepted in arguments/environment/files, and never saved or printed.
It is used only on the authenticated SSH stdin for one sudo -k invocation.
Import/help is inert. Scope and independent-review records are mandatory.
"""
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import shlex
import stat
import subprocess
import sys
import time
import warnings

ROOT = Path('/Users/daniel/Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101/execution/early-claims')
MIRROR = Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/execution/early-claims')
SOURCE = Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')
SSH_OPTIONS = (
    'HostName=100.121.130.51', 'User=chatops', 'Port=22', 'BatchMode=yes', 'ConnectTimeout=10',
    'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
    'UserKnownHostsFile=/Users/daniel/.ssh/known_hosts', 'GlobalKnownHostsFile=/dev/null',
    'KnownHostsCommand=none', 'HostKeyAlias=100.121.130.51', 'CanonicalizeHostname=no',
    'ProxyCommand=none', 'ProxyJump=none', 'PermitLocalCommand=no', 'RemoteCommand=none',
    'IdentityFile=/Users/daniel/.ssh/id_ed25519', 'IdentityAgent=none', 'IdentitiesOnly=yes',
    'CertificateFile=none', 'PreferredAuthentications=publickey', 'PasswordAuthentication=no',
    'KbdInteractiveAuthentication=no', 'GSSAPIAuthentication=no', 'HostbasedAuthentication=no',
    'ControlMaster=no', 'ControlPath=none', 'ForwardAgent=no', 'ClearAllForwardings=yes',
    'ServerAliveInterval=5', 'ServerAliveCountMax=2', 'LogLevel=ERROR')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def private(path):
    require(not path.is_symlink(), 'LOCAL_SYMLINK')
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and
            stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and s.st_size <= 65536,
            'PRIVATE_RECORD_PROFILE')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (s.st_dev, s.st_ino), 'RECORD_REPLACED')
        raw = os.read(fd, 65537)
        require(len(raw) == s.st_size, 'RECORD_SIZE')
        return raw
    finally:
        os.close(fd)


def paired_create(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
    require(len(raw) <= 65536, 'RECORD_BOUND')
    for root in (ROOT, MIRROR):
        fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        fd = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        require(private(root/name) == raw, 'CUSTODY_READBACK')


def validate():
    require(sys.platform == 'darwin' and os.geteuid() != 0 and len(sys.argv) == 1, 'MAC_USER_ENTRY')
    for root in (ROOT, MIRROR):
        require(root.resolve(strict=True) == root, 'CANONICAL_CUSTODY')
        s = root.stat()
        require(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'PRIVATE_CUSTODY')
        require(not (root/'ATTEMPT.json').exists() and not (root/'RESULT.json').exists(), 'NO_AUTOMATIC_REPLAY')
    scope_raw = private(ROOT/'SCOPE.json')
    require(scope_raw == private(MIRROR/'SCOPE.json'), 'SCOPE_CUSTODY')
    scope = json.loads(scope_raw)
    review_raw = private(ROOT/'INDEPENDENT_REVIEW.json')
    require(review_raw == private(MIRROR/'INDEPENDENT_REVIEW.json'), 'REVIEW_CUSTODY')
    review = json.loads(review_raw)
    require(review['verdict'] == 'PASS' and review['scope_sha256'] == sha(scope_raw) and
            review['independent_of_implementer'] is True and review['unresolved_findings'] == [],
            'INDEPENDENT_REVIEW_REQUIRED')
    files = {}
    for name, expected in scope['source_sha256'].items():
        require(name in ('tu1nz_mainserver_claim_read.py', 'tu1nz_mainserver_claim_transport.py'), 'FINITE_SOURCE_SET')
        path = SOURCE/name
        require(path.resolve(strict=True) == path, 'CANONICAL_SOURCE')
        raw = path.read_bytes()
        require(sha(raw) == expected, 'REVIEWED_SOURCE_DRIFT')
        files[name] = raw
    require(set(files) == {'tu1nz_mainserver_claim_read.py', 'tu1nz_mainserver_claim_transport.py'}, 'SOURCE_SET')
    require(scope['host_id'] == 109772243 and scope['transaction'] == 'public-rights-20261014-1' and
            scope['ssh_options_sha256'] == sha(json.dumps(SSH_OPTIONS, separators=(',', ':')).encode()),
            'SCOPE_HOST_OR_TRANSPORT_BINDING')
    return sha(scope_raw), sha(review_raw), files['tu1nz_mainserver_claim_read.py'], scope


def project_report(report, targets):
    """Reject unexpected fields instead of persisting arbitrary remote output."""
    require(type(report) is dict and set(report) == {'schema', 'transaction', 'machine_sha256',
            'boot_id', 'namespaces', 'targets', 'observed_ancestors', 'result', 'limits'}, 'OUTPUT_FIELDS')
    require(report['schema'] == 'TU1NZ_MAIN_SERVER_R4_EARLY_CLAIM_READ_V1' and
            report['transaction'] == 'public-rights-20261014-1' and
            report['machine_sha256'] == 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae' and
            re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', report['boot_id']),
            'OUTPUT_BINDING')
    require(set(report['namespaces']) == {'mnt', 'pid', 'user'} and all(
        re.fullmatch(name+r':\[[0-9]{1,20}\]', value) for name, value in report['namespaces'].items()),
        'NAMESPACE_PROJECTION')
    meta_keys = {'device', 'inode', 'type', 'mode', 'uid', 'gid'}
    def check_meta(row):
        require(set(row) == meta_keys and all(type(row[k]) is int and 0 <= row[k] < 2**64
                for k in meta_keys-{'mode'}) and re.fullmatch(r'0o[0-7]{1,4}', row['mode']),
                'METADATA_PROJECTION')
    allowed = {'/etc/machine-id', '/proc/sys/kernel/random/boot_id', *targets}
    allowed |= {str(p) for t in tuple(allowed) for p in PurePosixPath(t).parents if str(p) != '/'}
    require(type(report['targets']) is dict and set(report['targets']) == set(targets), 'TARGET_PROJECTION')
    for path, row in report['targets'].items():
        if row.get('state') == 'ABSENT':
            require(set(row) == {'state', 'first_absent_component', 'held_parent'} and
                    row['first_absent_component'] in {path, *(str(p) for p in PurePosixPath(path).parents)} and
                    row['held_parent'] == str(PurePosixPath(row['first_absent_component']).parent),
                    'ABSENCE_PROJECTION')
        else:
            require(row.get('state') == 'PRESENT' and set(row) == meta_keys|{'state'}, 'PRESENT_PROJECTION')
            check_meta({k: row[k] for k in meta_keys})
    require(type(report['observed_ancestors']) is dict and set(report['observed_ancestors']) <= allowed,
            'ANCESTOR_PROJECTION')
    for row in report['observed_ancestors'].values():
        check_meta(row)
    expected = ('NECESSARY_ABSENCES_OBSERVED' if all(row['state'] == 'ABSENT'
                for row in report['targets'].values()) else 'REQUIRED_ABSENCE_NOT_MET')
    require(report['result'] == expected and report['limits'] ==
            'METADATA_ONLY_POINT_OBSERVATION_NOT_WRITER_EXCLUSION_OR_EXECUTION_ADMISSION', 'RESULT_PROJECTION')
    return report


def communicate_bounded(process, secret):
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    try:
        process.stdin.write(secret)
        process.stdin.flush()
        process.stdin.close()
        secret[:] = b'\x00'*len(secret)
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            require(time.monotonic()-started < 35, 'SSH_WALL_TIME_BOUND')
            for key, _ in selector.select(timeout=0.25):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output[key.data].extend(chunk)
                    require(len(output[key.data]) <= 65536, 'SSH_OUTPUT_BOUND')
        process.wait(timeout=max(0.01, 35-(time.monotonic()-started)))
        return bytes(output['stdout']), bytes(output['stderr'])
    finally:
        secret[:] = b'\x00'*len(secret)
        selector.close()
        if process.poll() is None:
            # Only this locally created SSH process; never a remote service.
            process.kill()
            process.wait(timeout=5)
        for name in ('stdin', 'stdout', 'stderr'):
            stream = getattr(process, name)
            if stream is not None and not stream.closed:
                stream.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    scope_hash, review_hash, source, scope = validate()
    require(sys.stdin.isatty(), 'VISIBLE_PERSONAL_TTY_REQUIRED')
    # sudo -k WITH a command ignores any timestamp and does not update it.
    # No host-side files or script are uploaded. Python receives fixed source.
    command = shlex.join(['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/python3',
                          '-I', '-B', '-S', '-c', source.decode('utf-8')])
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T']
    for option in SSH_OPTIONS:
        argv.extend(('-o', option))
    argv.extend(('100.121.130.51', command))
    print('Hauptserver 109772243: einmalige reine Claim-Metadatenaufnahme. Keine Dienstaktion.')
    # getpass may otherwise fall back to visible input when termios fails.
    # Fail before fallback_getpass can perform any ordinary input read.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass('sudo-Passwort für chatops persönlich eingeben (unsichtbar): ')
    require(password and '\n' not in password and '\r' not in password and len(password) <= 1024,
            'PASSWORD_INPUT_REJECTED')
    secret = bytearray(password.encode()+b'\n')
    del password
    paired_create('ATTEMPT.json', {'scope_sha256': scope_hash, 'review_sha256': review_hash,
                                  'unix_time': time.time(), 'kind': 'READ_ONLY_SSH_INTENT_NOT_PRODUCTION_CLAIM'})
    result = {'scope_sha256': scope_hash, 'review_sha256': review_hash, 'result': 'UNKNOWN',
              'no_retry_automatically': True, 'host_mutation_requested': False}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        out, err = communicate_bounded(process, secret)
        result.update(ssh_exit=process.returncode, stdout_sha256=sha(out), stdout_bytes=len(out),
                      stderr_sha256=sha(err), stderr_bytes=len(err))
        # Never print/save raw stderr or unexpected output; no private values
        # from an unexpected command path can enter the custody report.
        if process.returncode == 0:
            report = project_report(json.loads(out), scope['targets'])
            result.update(result=report['result'], observation=report)
        else:
            result['error'] = 'SSH_OR_SUDO_OR_READER_DID_NOT_CONFIRM_READ'
    except BaseException as error:
        result['error'] = type(error).__name__
    finally:
        secret[:] = b'\x00'*len(secret)
        paired_create('RESULT.json', result)
    print('Ergebnis:', result['result'], '— private Rücklese wird getrennt geprüft.')
    return 0 if result['result'] == 'NECESSARY_ABSENCES_OBSERVED' else 1


if __name__ == '__main__':
    if sys.argv[1:] == ['--help']:
        print(__doc__)
    else:
        try:
            raise SystemExit(main())
        except Exception as error:
            print('Abbruch vor bestätigter Aufnahme:', type(error).__name__)
            raise SystemExit(1)
