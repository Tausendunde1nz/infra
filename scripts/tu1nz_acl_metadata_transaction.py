#!/usr/bin/env python3
"""Offline-reviewed metadata transaction. Live activation is deliberately locked."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

LIVE_PLAN_SHA256 = None  # No complete privileged inventory/dependency approval yet.


def snapshot(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('symlinks are outside transaction scope')
    s = path.stat()
    if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
        raise ValueError('unsupported file type')
    return {'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
            'dev': s.st_dev, 'inode': s.st_ino,
            'acl': subprocess.check_output(['getfacl', '-cpn', str(path)], text=True)}


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())


def normalize_to(path, wanted):
    """Exact ACL and mode only. Never chown, traverse, remove or replace a target."""
    subprocess.run(['setfacl', '--set-file=-', str(path)], input=wanted['acl'],
                   text=True, check=True, capture_output=True)
    os.chmod(path, wanted['mode'], follow_symlinks=False)


def compatible_identity(before, after):
    return all(before[k] == after[k] for k in ('uid', 'gid', 'dev', 'inode'))


def apply(plan, backup, fixture_root=None, fail_after=None):
    if fixture_root is None:
        raise RuntimeError('LIVE_LOCKED: complete privileged inventory and approved plan missing')
    root = Path(fixture_root).resolve(strict=True)
    if not (root / 'OFFLINE_FIXTURE').is_file():
        raise ValueError('isolated fixture marker missing')
    if not plan or not isinstance(plan, list):
        raise ValueError('empty/invalid plan')
    targets = []
    for entry in plan:
        path = Path(entry['path'])
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('path outside isolated fixture')
        if path in targets:
            raise ValueError('duplicate target')
        targets.append(path)
        if not compatible_identity(entry['before'], entry['after']):
            raise ValueError('ownership or identity changes forbidden')
    current = [snapshot(p) for p in targets]
    if all(s == e['after'] for s, e in zip(current, plan)):
        return 'ALREADY_APPLIED'
    if not all(s == e['before'] for s, e in zip(current, plan)):
        raise RuntimeError('baseline drift; no mutation')
    write_new(backup, {'plan': plan, 'sha256': hashlib.sha256(
        json.dumps(plan, sort_keys=True).encode()).hexdigest()})
    attempted = []
    try:
        for i, (path, entry) in enumerate(zip(targets, plan)):
            if snapshot(path) != entry['before']:
                raise RuntimeError('concurrent metadata drift')
            attempted.append((path, entry))
            normalize_to(path, entry['after'])
            if snapshot(path) != entry['after']:
                raise RuntimeError('postcondition mismatch')
            if fail_after == i:
                raise RuntimeError('injected offline failure')
        if [snapshot(p) for p in targets] != [e['after'] for e in plan]:
            raise RuntimeError('final mismatch')
        return 'APPLIED'
    except BaseException:
        # Only metadata on the same identities touched by this transaction.
        for path, entry in reversed(attempted):
            if not compatible_identity(snapshot(path), entry['before']):
                raise RuntimeError('rollback identity drift; manual review required')
            normalize_to(path, entry['before'])
            if snapshot(path) != entry['before']:
                raise RuntimeError('rollback verification failed')
        raise


def rollback(backup, fixture_root):
    saved = json.loads(Path(backup).read_text())
    plan = saved['plan']
    if hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest() != saved['sha256']:
        raise ValueError('backup checksum mismatch')
    reverse = [{'path': e['path'], 'before': e['after'], 'after': e['before']} for e in plan]
    return apply(reverse, str(backup) + '.rollback-proof.json', fixture_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.parse_args()
    raise SystemExit('LIVE_LOCKED: no reviewed complete live plan; metadata unchanged')
