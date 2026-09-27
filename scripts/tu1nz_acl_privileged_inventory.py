#!/usr/bin/env python3
"""Metadata/dependency collection only. No production chmod, ACL write or service call."""
import argparse
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

ROOTS = ('/var/lib/tausendunde1nz', '/var/log/tausendunde1nz')
BASE = Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=180)


def private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def collect(out):
    errors, entries = [], []
    for root in ROOTS:
        for base, dirs, files in os.walk(root, followlinks=False,
                onerror=lambda e: errors.append({'path': e.filename, 'error': type(e).__name__})):
            paths = [Path(base)] + [Path(base) / n for n in files]
            paths += [Path(base) / n for n in dirs if (Path(base) / n).is_symlink()]
            for path in paths:
                try:
                    s = path.lstat()
                    entries.append({'path': str(path), 'uid': s.st_uid, 'gid': s.st_gid,
                        'mode': stat.S_IMODE(s.st_mode), 'type': stat.S_IFMT(s.st_mode),
                        'inode': s.st_ino, 'dev': s.st_dev,
                        'link': os.readlink(path) if stat.S_ISLNK(s.st_mode) else None})
                except OSError as e:
                    errors.append({'path': str(path), 'error': type(e).__name__})
    private(out / 'metadata.jsonl', ''.join(json.dumps(e) + '\n' for e in entries).encode())
    acl = run(['getfacl', '-R', '-P', '-p', '-n', *ROOTS])
    private(out / 'metadata.acl', acl.stdout.encode())
    private(out / 'acl-errors.txt', acl.stderr.encode())
    groups = {e['gid'] for e in entries}
    groups.update(int(m[1]) for m in re.finditer(r'(?m)^(?:default:)?group:(\d+):', acl.stdout))
    members = []
    for gid in sorted(groups):
        try:
            g = grp.getgrgid(gid)
            item = {'gid': gid, 'name': g.gr_name, 'supplementary': g.gr_mem}
        except KeyError:
            item = {'gid': gid, 'name': None, 'supplementary': None}
        item['primary'] = [p.pw_name for p in pwd.getpwall() if p.pw_gid == gid]
        members.append(item)
    private(out / 'groups.json', json.dumps(members, indent=2).encode())
    processes, visibility = [], []
    for status in Path('/proc').glob('[0-9]*/status'):
        try:
            d = dict(line.split(':', 1) for line in status.read_text().splitlines() if ':' in line)
            refs = []
            for fd in (status.parent / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                    if target.startswith(ROOTS):
                        info = (status.parent / 'fdinfo' / fd.name).read_text()
                        flags = re.search(r'(?m)^flags:\s*(\d+)', info)
                        refs.append({'fd': fd.name, 'path': target,
                            'access_mode': int(flags[1], 8) & 3 if flags else None})
                except FileNotFoundError:
                    pass  # process/fd lifetime ended during read
                except PermissionError:
                    visibility.append({'pid': status.parent.name, 'fd': fd.name})
            # Save identity, never command arguments/environment or file contents.
            processes.append({'pid': status.parent.name, 'name': d['Name'].strip(),
                'uid': d['Uid'].strip(), 'gid': d['Gid'].strip(),
                'groups': d.get('Groups', '').strip(), 'open_targets': refs})
        except FileNotFoundError:
            pass
        except (PermissionError, KeyError) as e:
            visibility.append({'pid': status.parent.name, 'error': type(e).__name__})
    private(out / 'processes.json', json.dumps(processes, indent=2).encode())
    private(out / 'process-visibility.json', json.dumps(visibility, indent=2).encode())
    listing = run(['systemctl', 'list-unit-files', '--type=service', '--type=timer', '--type=path', '--no-legend', '--no-pager'])
    names = [x.split()[0] for x in listing.stdout.splitlines() if x.split()]
    props = ['Id', 'User', 'Group', 'SupplementaryGroups', 'DynamicUser', 'UMask',
        'FragmentPath', 'DropInPaths', 'MainPID', 'WorkingDirectory', 'ReadWritePaths',
        'ReadOnlyPaths', 'BindPaths', 'BindReadOnlyPaths', 'StateDirectory',
        'LogsDirectory', 'RuntimeDirectory', 'TriggeredBy', 'Triggers', 'ExecStart']
    units = run(['systemctl', 'show', *names, '--no-pager', *[x for p in props for x in ('-p', p)]])
    sanitized = []
    for block in units.stdout.split('\n\n'):
        d = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        ex = d.pop('ExecStart', '')
        d['executable_paths'] = re.findall(r'path=([^ ;}]+)', ex)
        d['direct_target_references'] = sorted(set(re.findall(r'/var/(?:lib|log)/tausendunde1nz[\w./-]*', ex)))
        sanitized.append(d)
    private(out / 'units.json', json.dumps(sanitized, indent=2).encode())
    scans = ['/usr/local/bin', '/etc/systemd/system', '/usr/lib/systemd/system',
             '/etc/logrotate.d', '/etc/tmpfiles.d', '/usr/lib/tmpfiles.d']
    references, scan_errors = [], []
    for root in scans:
        for base, dirs, files in os.walk(root, followlinks=False,
                onerror=lambda e: scan_errors.append({'path': e.filename, 'error': type(e).__name__})):
            for name in files:
                path = Path(base) / name
                try:
                    if not path.is_file() or path.stat().st_size > 2000000:
                        continue
                    data = path.read_bytes()
                    if b'\x00' in data:
                        continue
                    matches = [{'line': i, 'paths': sorted(set(re.findall(
                        r'/var/(?:lib|log)/tausendunde1nz[\w./-]*', line)))}
                        for i, line in enumerate(data.decode(errors='replace').splitlines(), 1)
                        if any(root in line for root in ROOTS)]
                    if matches:
                        references.append({'file': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'matches': matches})
                except OSError as e:
                    scan_errors.append({'path': str(path), 'error': type(e).__name__})
    private(out / 'references.json', json.dumps(references, indent=2).encode())
    private(out / 'reference-errors.json', json.dumps(scan_errors, indent=2).encode())
    ids = run(['docker', 'ps', '-aq'])
    containers = []
    docker_rc = ids.returncode
    if not docker_rc and ids.stdout.split():
        result = run(['docker', 'inspect', *ids.stdout.split()])
        docker_rc = result.returncode
        if not docker_rc:
            for c in json.loads(result.stdout):
                mounts = [{'source': m.get('Source'), 'destination': m.get('Destination'),
                           'rw': m.get('RW'), 'type': m.get('Type')} for m in c['Mounts']]
                containers.append({'name': c['Name'], 'pid': c['State']['Pid'],
                    'user': c['Config'].get('User'), 'mounts': mounts})
    private(out / 'docker-mounts.json', json.dumps(containers, indent=2).encode())
    result = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'entries': len(entries), 'walk_errors': errors, 'acl_rc': acl.returncode,
        'systemd_rc': [listing.returncode, units.returncode], 'docker_rc': docker_rc,
        'metadata_complete': not errors and acl.returncode == 0,
        'dependency_analysis_complete': False,
        'live_activation_authorized': False,
        'note': 'Snapshot is not atomic. Privileged evidence requires review and a new pinned plan; no automatic permission to apply.'}
    private(out / 'RESULT.json', json.dumps(result, indent=2).encode())
    private(out / 'SHA256.json', json.dumps({f.name: hashlib.sha256(f.read_bytes()).hexdigest()
        for f in out.iterdir() if f.is_file()}, indent=2).encode())
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--collect-only', required=True, action='store_true')
    p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Root needed for complete read-only inventory; no mutation performed')
    os.umask(0o077)
    out = BASE / ('acl-privileged-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(mode=0o700)
    result = collect(out)
    # Ownership change is limited to newly created evidence files, never source trees.
    for f in out.iterdir():
        os.chmod(f, 0o600)
        os.chown(f, 1001, 1001)
    os.chown(out, 1001, 1001)
    print('INVENTORY_ONLY', out, 'complete=' + str(result['metadata_complete']))
    print('LIVE_LOCKED: review privileged dependencies before preparing activation')


if __name__ == '__main__':
    main()
