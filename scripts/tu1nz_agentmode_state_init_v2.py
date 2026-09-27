#!/usr/bin/env python3
"""Agentmode state provisioning v2. Existing objects are validated, never repaired.

Historical runtime remains hash-bound and unchanged. Provision before first
observation; --check is read-only. Only the fixed production state root is exposed
by the CLI. Fixture provisioning is isolated to a private test root.
"""
import argparse
import os
from pathlib import Path
import pwd
import stat
import subprocess

PRODUCTION = Path('/var/lib/tausendunde1nz/agentmode')
HISTORICAL_SHA256 = '96a03614f5c5eacc94576975a7d38251b5cc3da7c673a690914942b298d359df'
STATE_FILES = frozenset({'control_update_state.json', 'last_sync.ok',
    'docs-checksums.txt', 'notification_state', 'monitor_last.txt'})
INTEGRITY_FILES = frozenset({'control-checksums.txt', 'docs-checksums.txt',
    'integrity_state.json', 'notification_state'})
# Audit-only exceptions OUTSIDE the writable scope. No exception is allowed
# beneath the Agentmode state root. staging is preserved, not declared minimal.
SHARED_READONLY_MATRIX = {
    '/var/log/tausendunde1nz/ape-approval/ingress/inbox': ('tu1nz-ape-broker', 'tu1nz-ape-notify', 0o2770),
    '/var/log/tausendunde1nz/ape-approval/ingress/staging/.producer.lock': ('tu1nz-ape-broker', 'tu1nz-ape-notify', 0o660),
    '/var/log/tausendunde1nz/ape-approval-notifier-state': ('root', 'tu1nz-ape-notify', 0o2770),
    '/var/log/tausendunde1nz/ape-approval/ingress/staging': ('tu1nz-ape-broker', 'tu1nz-ape-notify', 0o2770),
}

class UnsafeState(RuntimeError):
    pass

def acl(fd):
    raw = subprocess.check_output(['getfacl', '-cpn', '/proc/self/fd/' + str(fd)],
                                  pass_fds=(fd,), text=True)
    return dict(line.split('\t')[0].strip().rsplit(':', 1)
                for line in raw.splitlines() if line and not line.startswith('#'))

def expected_acl(uid, gid, setgid):
    result = {'user:': 'rwx', 'group:': 'r-x', 'mask:': 'r-x', 'other:': '---'}
    default = {'user:': 'rwx', 'group:': 'r-x', 'mask:': 'r-x', 'other:': '---'}
    if setgid:
        # Exact deployed profile: named owner is redundant, not another writer.
        result.update({'user:' + str(uid): 'rwx', 'group:' + str(gid): 'r-x'})
        default.update({'user:' + str(uid): 'rwx', 'group:' + str(gid): 'r-x', 'mask:': 'rwx'})
    result.update({'default:' + key: value for key, value in default.items()})
    return result

def require_identity(metadata, uid, gid, directory):
    correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not correct_type or metadata.st_uid != uid or metadata.st_gid != gid:
        raise UnsafeState('unexpected type, owner or group')

def require_inherited_acl(actual, uid, gid):
    allowed = {'user:', 'group:', 'mask:', 'other:', 'user:' + str(uid), 'group:' + str(gid)}
    for key, permissions in actual.items():
        base = key.removeprefix('default:')
        if base not in allowed or permissions not in {'---', 'r--', 'r-x', 'rw-', 'rwx'}:
            raise UnsafeState('unexpected inherited ACL entry')
        if base == 'other:' and permissions != '---':
            raise UnsafeState('unexpected inherited other access')

def open_parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise UnsafeState('absolute non-traversing path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise

def validate(fd, uid, gid, setgid, integrity=False):
    s = os.fstat(fd)
    require_identity(s, uid, gid, True)
    if stat.S_IMODE(s.st_mode) != (0o2750 if setgid else 0o750):
        raise UnsafeState('unexpected state directory mode')
    if acl(fd) != expected_acl(uid, gid, setgid):
        raise UnsafeState('unexpected state directory ACL')
    for name in os.listdir(fd):
        if not integrity and name == 'integrity':
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                validate(child, uid, gid, True, integrity=True)
            finally:
                os.close(child)
            continue
        if name not in (INTEGRITY_FILES if integrity else STATE_FILES):
            raise UnsafeState('unrecognized state entry')
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            s = os.fstat(child)
            require_identity(s, uid, gid, False)
            if stat.S_IMODE(s.st_mode) != 0o640:
                raise UnsafeState('state file must be exactly 0640')
            actual = acl(child)
            require_inherited_acl(actual, uid, gid)
            for key, value in actual.items():
                if key.startswith('default:'):
                    raise UnsafeState('default ACL on regular file')
                if key.startswith('group:') and 'w' in value and 'w' in actual.get('mask:', 'rwx'):
                    raise UnsafeState('group-writable state file')
        finally:
            os.close(child)

def provision(path, uid, gid, setgid, create=False):
    path = Path(path)
    integrity = path.name == "integrity"
    scope = path.parent if integrity else path
    if scope != PRODUCTION:
        if scope.name != "runtime-state":
            raise UnsafeState("path outside explicit provisioning scope")
        root = scope.parent.lstat()
        require_identity(root, os.geteuid(), os.getegid(), True)
        if stat.S_IMODE(root.st_mode) != 0o700:
            raise UnsafeState("fixture parent must be private 0700")
    parent = open_parent(path)
    if integrity:
        try:
            parent_setgid = bool(os.fstat(parent).st_mode & stat.S_ISGID)
            validate(parent, uid, gid, parent_setgid)
            if not setgid:
                raise UnsafeState('integrity requires setgid')
        except BaseException:
            os.close(parent)
            raise
    fd = -1
    created = False
    identity = None
    try:
        if create:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
                created = True
                st = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                identity = (st.st_dev, st.st_ino)
            except FileExistsError:
                pass
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        s = os.fstat(fd)
        require_identity(s, uid, gid, True)
        if created:
            if (s.st_dev, s.st_ino) != identity:
                raise UnsafeState('new directory replaced')
            require_inherited_acl(acl(fd), uid, gid)
            wanted = expected_acl(uid, gid, setgid)
            material = ''.join(key + ':' + value + '\n' for key, value in wanted.items())
            subprocess.run(['setfacl', '--set-file=-', '/proc/self/fd/' + str(fd)],
                input=material, text=True, pass_fds=(fd,), check=True, capture_output=True)
            os.fchmod(fd, 0o2750 if setgid else 0o750)
        validate(fd, uid, gid, setgid, integrity=integrity)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (s.st_dev, s.st_ino):
            raise UnsafeState('state directory identity changed')
        return 'CREATED' if created else 'VALIDATED_UNCHANGED'
    except BaseException:
        # Roll back only our own newly created, still empty inode. Never repair
        # or recursively remove an existing directory or concurrent additions.
        if created:
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                raise UnsafeState('rollback identity drift; no removal')
            os.rmdir(path.name, dir_fd=parent)
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def initialize_fixture(root, setgid=False, integrity=False):
    root = Path(root)
    s = root.lstat()
    require_identity(s, os.geteuid(), os.getegid(), True)
    if stat.S_IMODE(s.st_mode) != 0o700:
        raise UnsafeState('fixture root must be private 0700')
    result = provision(root / 'runtime-state', os.geteuid(), os.getegid(), setgid, create=True)
    if integrity:
        provision(root / 'runtime-state' / 'integrity', os.geteuid(), os.getegid(), True, create=True)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true')
    action.add_argument('--create', action='store_true')
    args = parser.parse_args()
    account = pwd.getpwnam('chatops')
    # Creation must run as its owner, never silently chown a newly created root object.
    if args.create and (os.geteuid(), os.getegid()) != (account.pw_uid, account.pw_gid):
        raise UnsafeState('create requires chatops:chatops')
    print(provision(PRODUCTION, account.pw_uid, account.pw_gid, True, create=args.create))
    print(provision(PRODUCTION / 'integrity', account.pw_uid, account.pw_gid, True, create=args.create))

if __name__ == '__main__':
    main()
