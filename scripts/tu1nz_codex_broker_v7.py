#!/usr/bin/python3 -I
"""Fixed diagnostic broker V7. Not installed; semantic closure remains gated.

The installed path and immutable root manifest are mandatory. Executing this
repository copy as root is rejected. No restart/deployment operation is granted.
"""
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import selectors
import signal
import time
import sys

PROGRAM = Path('/usr/local/sbin/tu1nz-codex-ops')
ROOT = Path('/var/lib/tu1nz-codex-ops')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'HOME': '/var/empty', 'PYTHONNOUSERSITE': '1'}
UNITS = ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service',
         'tu1nz-adult-public-s8-telegram.service', 'tu1nz-adult-public-s10-wms.service',
         'tu1nz_agentmode.service', 'tailscaled.service', 'ssh.service', 'fail2ban.service')
CONTAINERS = ('spicymila_bot', 'telegram_bot_mommyramona', 'tu1nz_cadvisor')
TARGETS = ('/etc/sudoers', '/etc/sudoers.d/99-dokuagent-pandoc',
           '/etc/sudoers.d/chatops-nopass', '/etc/group', '/etc/gshadow')
OPS = ('status', 'containers', 'journal-counts', 'security-backup')
COMMANDS = {
 'status': ('/usr/bin/systemctl', 'show', *UNITS, '-p', 'Id', '-p', 'ActiveState',
            '-p', 'SubState', '-p', 'Result', '-p', 'MainPID'),
 'containers': ('/usr/bin/docker', '--config', str(ROOT / 'docker'),
                '--host', 'unix:///var/run/docker.sock', 'inspect', *CONTAINERS),
 'journal-counts': ('/usr/bin/journalctl', '--no-pager', '-n', '200', '--since', '-1hour',
                    '--output=json', *sum((['-u', u] for u in UNITS), [])),
}


def parse(args):
    if len(args) != 1 or args[0] not in OPS:
        raise ValueError('operation_denied')
    return args[0]


def sudoers():
    return ''.join('chatops ALL=(root) NOPASSWD: NOSETENV: ' + str(PROGRAM) + ' ' + op + '\n' for op in OPS)


def safe(path, directory=False):
    path = Path(path)
    current = Path('/')
    for part in path.parts[1:]:
        current = current / part
        s = current.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o022:
            raise ValueError('unsafe_root_path')
        if current != path and not stat.S_ISDIR(s.st_mode):
            raise ValueError('ancestor_type')
        if hasattr(os, 'listxattr') and any('posix_acl' in x for x in os.listxattr(current)):
            raise ValueError('unexpected_acl')
    if directory:
        if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o700:
            raise ValueError('directory_mode')
    elif not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError('file_type')
    return s


def read(path):
    before = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        s = os.fstat(handle.fileno())
        if (s.st_dev, s.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('file_swap')
        data = handle.read(2_000_001)
        after = os.fstat(handle.fileno())
        if len(data) > 2_000_000 or (s.st_size, s.st_mtime_ns, s.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('file_drift')
    return data


def program_digest(path):
    before = safe(path)
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        current = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('program_swap')
        total = 0
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > 256 * 1024 * 1024:
                raise ValueError('program_size')
            digest.update(block)
        after = os.fstat(handle.fileno())
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('program_changed')
    return digest.hexdigest()


def emit_private(path, value):
    safe(Path(path).parent, directory=True)
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    temporary = Path(path).parent / ('.new-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if Path(path).exists() or Path(path).is_symlink():
            raise ValueError('unexpected_existing_output')
        os.rename(temporary, path)
        dfd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return hashlib.sha256(data).hexdigest()


def sanitize(operation, raw):
    if operation == 'status':
        result = []
        for line in raw.decode().splitlines():
            key, sep, value = line.partition('=')
            if sep and key in {'Id', 'ActiveState', 'SubState', 'Result', 'MainPID'}:
                if not re.fullmatch(r'[A-Za-z0-9_.@-]{0,100}', value):
                    raise ValueError('unexpected_status')
                result.append({key: value})
        return result
    if operation == 'containers':
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) != len(CONTAINERS):
            raise ValueError('container_set')
        result = []
        for c in data:
            name = c['Name'].lstrip('/')
            if name not in CONTAINERS:
                raise ValueError('container_name')
            state = c['State']['Status']
            health = c['State'].get('Health', {}).get('Status', 'none')
            if state not in {'running', 'exited', 'created', 'paused', 'restarting', 'dead', 'removing'} or health not in {'none', 'starting', 'healthy', 'unhealthy'}:
                raise ValueError('container_state')
            restart = c['RestartCount']
            if type(restart) is not int or restart < 0:
                raise ValueError('restart_count')
            result.append({'name': name, 'state': state, 'health': health, 'restarts': restart})
        if {r['name'] for r in result} != set(CONTAINERS):
            raise ValueError('container_set')
        return result
    if operation == 'journal-counts':
        counts = {str(i): 0 for i in range(8)}
        for line in raw.splitlines():
            item = json.loads(line)
            priority = str(item.get('PRIORITY', '6'))
            if priority not in counts:
                raise ValueError('journal_priority')
            counts[priority] += 1
        return counts
    raise ValueError('operation_denied')


def backup():
    # Additive backup only. On any read failure no successful backup is committed.
    # Fixed targets; no config modification and therefore no config rollback needed.
    record = {}
    for path in TARGETS:
        try:
            s = safe(path)
            data = read(path)
        except FileNotFoundError:
            record[path] = {'absent': True}
            continue
        record[path] = {'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'base64': base64.b64encode(data).decode()}
    name = 'backup-' + secrets.token_hex(16) + '.json'
    digest = emit_private(ROOT / name, record)
    return {'backup': name, 'sha256': digest}


def run_bounded(command, timeout=20, limit=2_000_000):
    """Bound both streams during collection; kill/wait the entire helper group."""
    start=time.monotonic()
    with subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,env=ENV,cwd='/',start_new_session=True) as p:
        selector=selectors.DefaultSelector()
        buffers={'out':bytearray(),'err':bytearray()}
        try:
            selector.register(p.stdout,selectors.EVENT_READ,'out')
            selector.register(p.stderr,selectors.EVENT_READ,'err')
            while selector.get_map():
                remaining=timeout-(time.monotonic()-start)
                if remaining<=0:raise ValueError('diagnostic_timeout')
                for key,event in selector.select(min(remaining,0.2)):
                    block=os.read(key.fileobj.fileno(),65536)
                    if not block:selector.unregister(key.fileobj);continue
                    buffers[key.data].extend(block)
                    if sum(map(len,buffers.values()))>limit:raise ValueError('diagnostic_size')
            remaining=timeout-(time.monotonic()-start)
            if remaining<=0:raise ValueError('diagnostic_timeout')
            rc=p.wait(timeout=remaining)
            if rc or buffers['err']:raise ValueError('diagnostic_failed')
            return bytes(buffers['out'])
        finally:
            selector.close()
            # On failure kill before reaping the group leader, avoiding PID reuse.
            if p.returncode is None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait()


def quota():
    # Bounded private storage: exhaustion fails closed, never deletes old evidence.
    count=0;total=0
    for path in ROOT.iterdir():
        if path.name.startswith(('audit-','backup-')):
            st=safe(path);count+=1;total+=st.st_size
    if count>=8192 or total>=32*1024*1024:
        raise ValueError('private_evidence_quota')


def main():
    caller = os.environ.get('SUDO_UID')
    origin = os.environ.get('SUDO_USER')
    os.environ.clear()
    os.environ.update(ENV)
    os.umask(0o077)
    if os.geteuid() != 0 or caller != '1001' or origin != 'chatops' or Path(__file__) != PROGRAM:
        return 77
    try:
        safe(ROOT, directory=True)
        manifest = json.loads(read(ROOT / 'manifest.json'))
        if hashlib.sha256(read(PROGRAM)).hexdigest() != manifest['program_sha256']:
            raise ValueError('program_drift')
        for op, command in COMMANDS.items():
            # /usr/bin programs are checked against the root-installed manifest.
            if program_digest(command[0]) != manifest['programs'][command[0]]:
                raise ValueError('helper_drift')
        safe(ROOT / 'lock')
        lock = os.open(ROOT / 'lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            quota()
            operation = 'rejected'
            outcome, rc, result = 'DENIED', 77, None
            try:
                operation = parse(sys.argv[1:])
                emit_private(ROOT / ('audit-start-' + secrets.token_hex(16) + '.json'),
                             {'operation': operation, 'caller_uid': 1001, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'result': 'STARTED'})
                if operation == 'security-backup':
                    result = backup()
                else:
                    result = sanitize(operation, run_bounded(COMMANDS[operation]))
                outcome, rc = 'OK', 0
            except Exception:
                pass
            emit_private(ROOT / ('audit-end-' + secrets.token_hex(16) + '.json'),
                         {'operation': operation, 'caller_uid': 1001, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'result': outcome, 'rc': rc})
            print(json.dumps({'status': outcome, 'result': result if rc == 0 else None}, sort_keys=True))
            return rc
        finally:
            os.close(lock)
    except Exception:
        print('{"status":"DENIED"}')
        return 77


if __name__ == '__main__':
    raise SystemExit(main())
