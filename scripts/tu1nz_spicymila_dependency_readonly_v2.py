"""Version 2: fixed-scope read-only collection, durable metadata-only evidence.

Exit 0: COMPLETE; 2: safe partial results / INCOMPLETE; 3: no safe result store.
No sudo invocation is made by this program. Production CLI accepts no arguments.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

VERSION = "2.0.0"
BASE = Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')
TERMS = ('tausendunde1nz_net', '172.25.0.3', '172.25.0.2',
         'spicymila_bot', 'telegram_bot_mommyramona', 'docker network connect',
         'watch_spicymila', 'watch_mommyramona', '8090', '8081')
MAX_LINE = 65536
MAX_RECORDS = 5000


class Interrupted(Exception):
    pass


def safe_error(exc=None, kind=None):
    # Never include str(exc), argv, stderr, environment values or journal messages.
    classes = {FileNotFoundError: 'FileNotFoundError', PermissionError: 'PermissionError',
               TimeoutError: 'TimeoutError', Interrupted: 'Interrupted',
               ValueError: 'ValueError', RuntimeError: 'RuntimeError', MemoryError: 'MemoryError',
               KeyboardInterrupt: 'KeyboardInterrupt', BrokenPipeError: 'BrokenPipeError', OSError: 'OSError'}
    name = next((v for k, v in classes.items() if isinstance(exc, k)), 'UnexpectedException')
    messages = {'timeout': 'Fixed monotonic deadline exceeded.',
                'returncode': 'Read-only child returned a nonzero exit code.',
                'invalid_json': 'Malformed metadata record rejected.',
                'limit': 'Input or result bound exceeded; coverage incomplete.',
                'exception': 'Section failed; external error text suppressed.'}
    if isinstance(exc, TimeoutError) and kind is None:
        kind = 'timeout'
    kind = kind if kind in messages else 'exception'
    return {'kind': kind, 'exception_class': name if exc else None,
            'message': messages[kind][:160]}


class Store:
    """Anchor every write to verified directory descriptors; refuse existing runs."""
    def __init__(self, base, name):
        if not re.fullmatch(r'collector-v2-[0-9TZ-]+-[0-9a-f]{12}', name):
            raise ValueError('invalid run name')
        base = Path(base)
        if not base.is_absolute():
            raise ValueError('absolute base required')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in base.parts[1:]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid not in (0, os.getuid()):
                # Production private base belongs to the explicitly confirmed chatops account.
                import pwd
                if stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != pwd.getpwnam('chatops').pw_uid:
                    raise PermissionError('unsafe base')
            os.mkdir(name, mode=0o700, dir_fd=fd)  # EEXIST is fatal, even if empty.
            self.fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            self.owner = (st.st_uid, st.st_gid)
            if os.geteuid() == 0:
                os.fchown(self.fd, *self.owner)
            os.fchmod(self.fd, 0o700)
            os.fsync(fd)
            self.path = base / name
            self.entries = {}
        finally:
            os.close(fd)

    def write(self, name, value):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            return self._write(name, value)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def _write(self, name, value):
        if not re.fullmatch(r'[a-z0-9_-]+\.json', name):
            raise ValueError('invalid artifact name')
        if set(os.listdir(self.fd)) != set(self.entries):
            raise FileExistsError('foreign directory entry')
        if name in os.listdir(self.fd):
            raise FileExistsError('artifact already exists')
        data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        tmp = '.pending-' + uuid.uuid4().hex
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            if os.geteuid() == 0:
                os.fchown(fd, *self.owner)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb', closefd=False) as out:
                out.write(data)
                out.flush()
                os.fsync(fd)
            # Directory is private; all artifact names are single-use, no foreign files accepted.
            if name in os.listdir(self.fd):
                raise FileExistsError('foreign artifact')
            os.rename(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            self.entries[name] = {'sha256': hashlib.sha256(data).hexdigest(),
                                  'bytes': len(data), 'mode': '0600'}
        finally:
            os.close(fd)
            try:
                os.unlink(tmp, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def close(self):
        os.close(self.fd)


def stop_child(p):
    # All children run in a dedicated process group. Kill descendants even if leader exited.
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        p.wait(timeout=0.3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait(timeout=2)
    # SIGKILL delivery is asynchronous; wait for all executable group members, not just leader.
    deadline = time.monotonic() + 2
    while True:
        running = False
        for item in Path('/proc').iterdir():
            if not item.name.isdigit():
                continue
            try:
                fields = (item / 'stat').read_text().rsplit(')', 1)[1].split()
            except (OSError, IndexError):
                continue
            if int(fields[2]) == p.pid and fields[0] != 'Z':
                running = True
                break
        if not running:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('child process group did not terminate')
        time.sleep(0.01)


def stream(command, parser, timeout=15.0):
    start = time.monotonic_ns()
    result = {'start_monotonic_ns': start, 'records': [], 'errors': [],
              'timeout': False, 'returncode': None, 'stdout_bytes': 0, 'stderr_bytes': 0}
    p = None
    sel = selectors.DefaultSelector()
    buf = b''
    dropping = False

    def consume(line):
        try:
            record = parser(line.decode('utf-8', errors='strict'))
        except (ValueError, UnicodeError):
            if not any(e['kind'] == 'invalid_json' for e in result['errors']):
                result['errors'].append(safe_error(kind='invalid_json'))
            return
        if record is not None:
            if len(result['records']) < MAX_RECORDS:
                result['records'].append(record)
            elif not any(e['kind'] == 'limit' for e in result['errors']):
                result['errors'].append(safe_error(kind='limit'))

    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                          'LC_ALL': 'C'})
        for pipe, label in [(p.stdout, 'stdout'), (p.stderr, 'stderr')]:
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ, label)
        while sel.get_map():
            if (time.monotonic_ns() - start) / 1e9 >= timeout:
                result['timeout'] = True
                result['errors'].append(safe_error(TimeoutError(), 'timeout'))
                stop_child(p)
                break
            for key, _ in sel.select(0.05):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                result[key.data + '_bytes'] += len(chunk)
                if key.data == 'stderr':
                    continue  # Discard immediately, never save raw stderr.
                for part in chunk.splitlines(keepends=True):
                    newline = part.endswith(b'\n')
                    if not dropping:
                        buf += part
                        if len(buf) > MAX_LINE:
                            buf = b''
                            dropping = True
                            if not any(e['kind'] == 'limit' for e in result['errors']):
                                result['errors'].append(safe_error(kind='limit'))
                        elif newline:
                            consume(buf)
                            buf = b''
                    if newline:
                        dropping = False
        if buf and not result['timeout']:
            consume(buf)
        remaining = timeout - (time.monotonic_ns() - start) / 1e9
        try:
            result['returncode'] = p.wait(timeout=max(0.01, remaining))
        except subprocess.TimeoutExpired:
            result['timeout'] = True
            result['errors'].append(safe_error(TimeoutError(), 'timeout'))
            stop_child(p)
            result['returncode'] = p.returncode
        if result['returncode'] and not result['timeout']:
            result['errors'].append(safe_error(kind='returncode'))
    except Interrupted:
        raise
    except Exception as exc:
        result['timeout'] = result['timeout'] or isinstance(exc, TimeoutError)
        result['errors'].append(safe_error(exc))
    finally:
        if p:
            stop_child(p)
            p.stdout.close()
            p.stderr.close()
        sel.close()
        result['end_monotonic_ns'] = time.monotonic_ns()
    return result


def journal_record(line):
    row = json.loads(line)
    if not isinstance(row, dict):
        raise ValueError('object required')
    stamp = row.get('__REALTIME_TIMESTAMP', '')
    if not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{1,20}', stamp):
        raise ValueError('timestamp required')
    message = row.get('MESSAGE', '')
    if not isinstance(message, str):
        raise ValueError('message type')
    hits = [t for t in TERMS if t in message]
    return {'timestamp_us': stamp, 'terms': hits} if hits else None


def nat_record(line):
    port = re.search(r'--dport (8090|8081)(?: |$)', line)
    dst = re.search(r'--to-destination (172\.[0-9.]+:[0-9]+)(?: |$)', line)
    return {'host_port': int(port[1]), 'destination': dst[1]} if port and dst else None


def files_metadata(roots):
    rows = []
    errors = []
    paths = []
    for root in roots:
        p = Path(root)
        if p.is_symlink():
            paths.append(p)
        elif p.is_dir():
            def onerror(exc):
                errors.append(safe_error(exc))
            for base, dirs, names in os.walk(p, followlinks=False, onerror=onerror):
                dirs[:] = [n for n in dirs if not (Path(base) / n).is_symlink()]
                paths.extend(Path(base) / n for n in names)
        else:
            paths.append(p)
    for p in sorted(set(paths)):
        fd = None
        try:
            if p.is_symlink():
                rows.append({'path': str(p), 'type': 'symlink', 'followed': False})
                continue
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 2_000_000:
                errors.append(safe_error(kind='limit'))
                continue
            with os.fdopen(os.dup(fd), 'rb') as f:
                data = f.read(2_000_001)
            after = os.fstat(fd)
            if len(data) > 2_000_000 or (st.st_ino, st.st_size, st.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError('unstable source')
            lines = data.decode(errors='replace').splitlines()
            rows.append({'path': str(p), 'uid': st.st_uid, 'gid': st.st_gid,
                         'mode': oct(stat.S_IMODE(st.st_mode)),
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'references': {t: [i + 1 for i, line in enumerate(lines) if t in line]
                                        for t in TERMS if any(t in line for line in lines)}})
        except Exception as exc:
            errors.append(safe_error(exc))
        finally:
            if fd is not None:
                os.close(fd)
    return {'records': rows, 'errors': errors}


class Collector:
    def __init__(self, store):
        self.store = store
        self.sections = []
        self.incomplete = False

    def section(self, name, fn):
        start = time.monotonic_ns()
        data = None
        caught = None
        try:
            data = fn()
        except BaseException as exc:
            caught = exc
            data = {'errors': [safe_error(exc)], 'timeout': isinstance(exc, TimeoutError)}
        end = time.monotonic_ns()
        errors = data.get('errors', [])
        result = {'section': name, 'start_monotonic_ns': start,
                  'end_monotonic_ns': end, 'returncode': data.get('returncode'),
                  'timeout': data.get('timeout', False), 'data': data,
                  'status': 'ERROR' if errors else 'OK'}
        self.store.write(name + '.json', result)
        if errors:
            self.store.write(name + '-error.json', {k: result[k] for k in
                ['section', 'start_monotonic_ns', 'end_monotonic_ns', 'returncode', 'timeout']} | {'errors': errors})
            self.incomplete = True
        self.sections.append({'name': name, 'status': result['status']})
        if caught and not isinstance(caught, (OSError, ValueError)):
            raise caught

    def run(self, sections):
        interrupted = False
        current = None
        current_start = time.monotonic_ns()
        try:
            for name, fn in sections:
                current = name
                current_start = time.monotonic_ns()
                self.section(name, fn)
        except BaseException as exc:
            interrupted = True
            self.incomplete = True
            self.store.write('interruption.json', {'section': current,
                'start_monotonic_ns': current_start, 'end_monotonic_ns': time.monotonic_ns(),
                'returncode': None, 'timeout': False, 'errors': [safe_error(exc)]})
        finally:
            # Prevent a second termination request from interrupting final manifest publication.
            old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                self.store.write('manifest.json', {'version': VERSION,
                    'status': 'INCOMPLETE' if self.incomplete else 'COMPLETE',
                    'interrupted_or_unexpected_exception': interrupted,
                    'end_monotonic_ns': time.monotonic_ns(), 'sections': self.sections,
                    'artifacts': self.store.entries.copy()})
            finally:
                for sig, handler in old.items():
                    signal.signal(sig, handler)
        return 2 if self.incomplete else 0


def journal_sections(now):
    start = dt.datetime(2025, 10, 12, tzinfo=dt.timezone.utc)
    index = 0
    while start < now:
        end = min(start + dt.timedelta(days=7), now)
        # journalctl has inclusive boundaries; overlaps are disclosed, never summed as unique events.
        cmd = ['/usr/bin/journalctl', '--no-pager', '-o', 'json', '--since', start.isoformat(),
               '--until', end.isoformat(), '-u', 'docker.service', '-u', 'cron.service',
               '--grep', '|'.join(re.escape(t) for t in TERMS)]
        def collect(cmd=cmd, start=start, end=end):
            r = stream(cmd, journal_record, timeout=15)
            r['window'] = {'since': start.isoformat(), 'until': end.isoformat(), 'inclusive_boundaries': True}
            return r
        yield ('journal-%03d' % index, collect)
        start = end
        index += 1


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        print('FATAL: confirmed privileged invocation required; no collection performed.')
        return 3
    now = dt.datetime.now(dt.timezone.utc)
    name = 'collector-v2-' + now.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
    try:
        store = Store(BASE, name)
    except BaseException:
        print('FATAL: safe private result directory could not be created.')
        return 3
    def interrupt(signum, frame):
        raise Interrupted()
    old = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        sections = [('run', lambda: {'version': VERSION, 'utc': now.isoformat(),
                    'python_version': list(sys.version_info[:3]), 'uid': os.getuid(),
                    'launcher_verified_sha256': globals().get('__verified_script_sha256__'),
                    'historical_commit': 'fe2a806c787584ad6e5013fe4019c9191e647d33',
                    'historical_v1_sha256': '29ff4d5261e4f8fa3bcf0ac82a8763b02490bbe19dca402815a19accb3b6fd75',
                    'journal_window_days': 7, 'journal_timeout_seconds': 15,
                    'max_line_bytes': MAX_LINE, 'max_records_per_command': MAX_RECORDS}),
                    ('protected-files', lambda: files_metadata([
                        '/etc/systemd/system', '/usr/local/bin', '/etc/cron.d',
                        '/var/spool/cron/crontabs', '/etc/crontab', '/opt/telegram_chatbot/.env'])),
                    ('proxy', lambda: files_metadata(['/etc/nginx']))]
        sections.extend(journal_sections(now))
        sections.append(('nat', lambda: stream(['/usr/sbin/iptables-save', '-t', 'nat'], nat_record)))
        result = Collector(store).run(sections)
        print(json.dumps({'status': 'COMPLETE' if result == 0 else 'INCOMPLETE',
                          'exitcode': result, 'result_directory': str(store.path)}))
        return result
    except BaseException as exc:
        # Storage loss can make even a manifest impossible; do not misreport success or exit 1.
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        valid_manifest = 'manifest.json' in store.entries
        if not valid_manifest:
            try:
                store.write('setup-error.json', {'section': 'setup-or-finalization',
                    'start_monotonic_ns': time.monotonic_ns(), 'end_monotonic_ns': time.monotonic_ns(),
                    'returncode': None, 'timeout': False, 'errors': [safe_error(exc)]})
                store.write('manifest.json', {'version': VERSION, 'status': 'INCOMPLETE',
                    'interrupted_or_unexpected_exception': True, 'sections': [],
                    'artifacts': store.entries.copy(), 'end_monotonic_ns': time.monotonic_ns()})
                valid_manifest = True
            except BaseException:
                pass
        print(json.dumps({'status': 'INCOMPLETE', 'exitcode': 2,
                          'result_directory': str(store.path), 'manifest_present': valid_manifest}))
        return 2
    finally:
        store.close()
        for sig, handler in old.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    sys.exit(main())
