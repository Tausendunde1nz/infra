#!/usr/bin/python3 -I
"""Fixed, read-only privileged follow-up. Never run during preparation.

Root writes ONLY into a new root-owned private result directory below a checked
root-owned /var/lib parent. No outputs go through chatops-controlled paths.
No shell, journal payload, environment values, service action or Docker command.
Exit 0 complete, 2 partial evidence, 3 unsafe output initialization.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time

BASE = Path('/var/lib/tu1nz-privilege-audit-v4')
FILES = (
 '/etc/crontab', '/var/spool/cron/crontabs/root', '/var/spool/cron/crontabs/chatops',
 '/usr/local/bin/aide_daily.sh', '/usr/local/bin/backup_notify.sh',
 '/usr/local/bin/doku_agent_health.sh', '/usr/local/bin/tu1nz-ape-notify-core',
 '/usr/local/bin/tw_youtube_live.sh', '/usr/local/bin/trendwatch_post.sh',
 '/usr/local/bin/trendwatch_fetch.sh', '/usr/local/bin/tw_affiliate.sh',
 '/usr/local/bin/tu1nz_sync_all.sh', '/etc/systemd/system/tu1nz_agentmode.service',
)
TREES = ('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly',
         '/etc/cron.monthly', '/var/spool/cron/crontabs')
TERMS = ('/opt/trendwatch/', 'today_title.txt', 'today_live_title.txt',
         'tw_youtube_live.sh', 'trendwatch_post.sh', '/var/log/tausendunde1nz',
         '/var/lib/tausendunde1nz', '/opt/tu1nz_repos')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def summary(data):
    text = data.decode('utf-8', errors='replace')
    result = {'bytes': len(data), 'sha256': sha(data), 'references': [], 'write_syntax_lines': [], 'literal_path_metadata': []}
    for n, line in enumerate(text.splitlines(), 1):
        matched = [term for term in TERMS if term in line]
        if matched:
            result['references'].append({'line': n, 'known_terms': matched})
        if re.search(r'\b(?:tee|mkdir|chown|chmod|install)\b|>>?|write_text|write_bytes|appendFile|writeFile', line):
            result['write_syntax_lines'].append(n)
    # Only literal absolute filesystem paths, never URL/query/credential values.
    paths = sorted(set(re.findall(r'(?<![A-Za-z0-9:/])/(?:usr/local|opt|var/log|var/lib|etc|run)/[A-Za-z0-9_./-]+', text)))
    for path in paths[:128]:
        if len(path) > 240:
            continue
        try:
            s = os.lstat(path)
            item = {'path': path, 'uid': s.st_uid, 'gid': s.st_gid,
                    'mode': oct(stat.S_IMODE(s.st_mode)), 'symlink': stat.S_ISLNK(s.st_mode)}
            if hasattr(os, 'listxattr') and not item['symlink']:
                item['acls'] = {a: os.getxattr(path, a, follow_symlinks=False).hex()
                                for a in os.listxattr(path, follow_symlinks=False) if 'posix_acl' in a}
            result['literal_path_metadata'].append(item)
        except FileNotFoundError:
            result['literal_path_metadata'].append({'path': path, 'absent': True})
        except OSError as exc:
            result['literal_path_metadata'].append({'path': path, 'error_class': type(exc).__name__})
    # Never include source lines, messages, environment values or command output.
    return result


def protected_directory(path, create=False):
    path = Path(path)
    current = Path('/')
    for part in path.parts[1:]:
        current = current / part
        try:
            s = current.lstat()
        except FileNotFoundError:
            if not create or current != path:
                raise
            current.mkdir(mode=0o700)
            s = current.lstat()
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or
                stat.S_IMODE(s.st_mode) & 0o022):
            raise ValueError('untrusted_output_ancestor')
        if hasattr(os, 'listxattr') and any('posix_acl' in x for x in os.listxattr(current)):
            raise ValueError('output_acl')
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('output_mode')


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.hashes = {}
        self.entries = []

    def write(self, name, data):
        if not re.fullmatch(r'[a-z0-9.-]+', name):
            raise ValueError('output_name')
        temporary = self.directory / ('.tmp-' + secrets.token_hex(16))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            target = self.directory / name
            if target.exists() or target.is_symlink():
                raise ValueError('output_exists')
            os.rename(temporary, target)
            dfd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            self.hashes[name] = sha(data)
        finally:
            if temporary.exists():
                temporary.unlink()

    def section(self, name, action):
        start = time.monotonic_ns()
        try:
            result = action()
            entry = {'section': name, 'status': 'OK', 'result': result}
        except BaseException as exc:
            entry = {'section': name, 'status': 'INCOMPLETE', 'exception_class': type(exc).__name__}
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            if 'entry' in locals():
                entry['start_monotonic_ns'] = start
                entry['end_monotonic_ns'] = time.monotonic_ns()
                self.entries.append(entry)
                self.write(name + '.json', json.dumps(entry, sort_keys=True).encode())
        return entry


def read_file(path, store, index):
    p = Path(path)
    # All ancestors checked for links; raw material is read, never interpreted/executed.
    current = Path('/')
    for part in p.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError('input_link')
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'path': str(p), 'absent': True}
    with os.fdopen(fd, 'rb') as handle:
        s = os.fstat(handle.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_size > 2_000_000:
            raise ValueError('input_type_or_size')
        data = handle.read(2_000_001)
        after = os.fstat(handle.fileno())
        if (len(data) > 2_000_000 or (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('input_changed')
    store.write('raw-%04d.bin' % index, data)
    acls = {}
    if hasattr(os, 'listxattr'):
        for attr in os.listxattr(p, follow_symlinks=False):
            if 'posix_acl' in attr:
                acls[attr] = os.getxattr(p, attr, follow_symlinks=False).hex()
    return {'path': str(p), 'uid': s.st_uid, 'gid': s.st_gid, 'mode': oct(stat.S_IMODE(s.st_mode)),
            'device': s.st_dev, 'inode': s.st_ino, 'nlink': s.st_nlink, 'acls': acls,
            'content_summary': summary(data)}


def unit_states():
    units = ['trendwatch2-' + context + '.' + suffix for context in
             ('morning', 'midday', 'afternoon', 'evening') for suffix in ('service', 'timer')]
    units += ['tu1nz_agentmode.service', 'trendwatch-fetch.service', 'trendwatch_tu1nz.service']
    properties = ['Id', 'LoadState', 'User', 'Group', 'ActiveState', 'SubState', 'Persistent',
                  'RandomizedDelayUSec', 'AccuracyUSec', 'NextElapseUSecRealtime',
                  'LastTriggerUSec', 'ProtectSystem', 'NoNewPrivileges']
    command = ['/usr/bin/systemctl', 'show', *units]
    for key in properties:
        command += ['-p', key]
    result = subprocess.run(command, env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode or result.stderr or len(result.stdout) > 100000:
        raise ValueError('unit_read_failed')
    records = []
    for line in result.stdout.decode().splitlines():
        key, separator, value = line.partition('=')
        if separator and key in properties:
            if key == 'LoadState' and value != 'loaded':
                raise ValueError('unit_not_loaded')
            records.append({key: value})
        elif line:
            raise ValueError('unexpected_unit_output')
    if {r['Id'] for r in records if 'Id' in r} != set(units):
        raise ValueError('unit_set')
    return records


def process_writers():
    observations = []
    inaccessible = 0
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            uid = int(status['Uid'].split()[1])
            caps = int(status.get('CapEff', '0').strip(), 16)
            if uid != 0 and caps == 0:
                continue
            for fdpath in (proc / 'fd').iterdir():
                try:
                    target = os.readlink(fdpath)
                    if not target.startswith(('/opt/', '/var/log/tausendunde1nz/', '/var/lib/tausendunde1nz/', '/app/', '/config/', '/cache/')):
                        continue
                    info = (proc / 'fdinfo' / fdpath.name).read_text()
                    flags = next(int(line.split()[1], 8) for line in info.splitlines() if line.startswith('flags:'))
                    if flags & os.O_ACCMODE not in (os.O_WRONLY, os.O_RDWR):
                        continue
                    st = fdpath.stat()
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    observations.append({'pid': int(proc.name), 'effective_uid': uid,
                                         'capabilities_nonzero': caps != 0, 'fd': int(fdpath.name),
                                         'target': target, 'target_uid': st.st_uid,
                                         'target_gid': st.st_gid, 'target_mode': oct(stat.S_IMODE(st.st_mode))})
                except (OSError, ValueError, StopIteration):
                    inaccessible += 1
        except (OSError, KeyError, ValueError):
            inaccessible += 1
    return {'observations': observations, 'raced_or_inaccessible': inaccessible,
            'limitation': 'Instantaneous descriptors only; absence is not proof of no writer.'}


def main():
    if len(sys.argv) != 1 or os.getuid() != 0 or os.geteuid() != 0:
        return 3
    source_sha = globals().get('_VERIFIED_SOURCE_SHA256', '')
    if not re.fullmatch('[0-9a-f]{64}', source_sha):
        return 3
    os.environ.clear()
    os.environ.update(ENV)
    os.umask(0o077)
    try:
        protected_directory(BASE, create=True)
        directory = BASE / ('run-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8))
        directory.mkdir(mode=0o700)
        protected_directory(directory)
    except Exception:
        print('{"status":"UNSAFE_OUTPUT_INITIALIZATION"}')
        return 3
    store = Store(directory)
    interrupted = False
    def interrupt(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        paths = list(FILES)
        for tree in TREES:
            try:
                paths += [str(p) for p in sorted(Path(tree).iterdir()) if not p.is_dir()]
            except OSError:
                store.section('tree-' + str(len(store.entries)), lambda: (_ for _ in ()).throw(ValueError('unreadable_tree')))
        for index, path in enumerate(dict.fromkeys(paths)):
            store.section('file-%04d' % index, lambda p=path, i=index: read_file(p, store, i))
        store.section('units', unit_states)
        store.section('privileged-open-writers', process_writers)
    except BaseException:
        interrupted = True
    status = 'COMPLETE' if not interrupted and all(e['status'] == 'OK' for e in store.entries) else 'INCOMPLETE'
    manifest = {'version': '4.0.0', 'source_sha256': source_sha, 'status': status, 'interrupted': interrupted,
                'file_hashes': store.hashes.copy(), 'sections': store.entries}
    payload = json.dumps(manifest, sort_keys=True).encode()
    store.write('manifest.json', payload)
    # Sanitized review report only. Raw files remain root:root0600 in0700 directories.
    print(json.dumps({'directory': str(directory), 'manifest_sha256': sha(payload),
                      'status': status, 'sections': store.entries}, sort_keys=True))
    return 0 if status == 'COMPLETE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
