"""Test-only Linux process termination evidence. No signals or live mutations."""
import errno
import os
from pathlib import Path
import time


def identity(pid):
    fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'state': fields[0], 'pgrp': int(fields[2]),
            'start': int(fields[19])}


def missing_confirmed(pid, read=identity, probe=os.kill):
    # A failed read alone is never sufficient, including ESRCH during read().
    try:
        probe(pid, 0)
    except ProcessLookupError as exc:
        if exc.errno != errno.ESRCH:
            raise
    else:
        return False
    try:
        read(pid)
    except (FileNotFoundError, ProcessLookupError) as exc:
        if exc.errno not in (errno.ENOENT, errno.ESRCH):
            raise
        return True
    return False


def stopped(expected, read=identity, probe=os.kill):
    try:
        now = read(expected['pid'])
    except (FileNotFoundError, ProcessLookupError) as exc:
        if exc.errno not in (errno.ENOENT, errno.ESRCH):
            raise
        return missing_confirmed(expected['pid'], read, probe)
    if (now['start'], now['pgrp']) != (expected['start'], expected['pgrp']):
        raise ValueError('pid_identity_changed')
    return now['state'] in ('Z', 'X')


def group_stopped(group, enumerate_pids=lambda: [int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal()], read=identity, probe=os.kill):
    for pid in enumerate_pids():
        try:
            item = read(pid)
        except (FileNotFoundError, ProcessLookupError) as exc:
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                raise
            if not missing_confirmed(pid, read, probe):
                return False
            continue
        if item['pgrp'] == group and item['state'] not in ('Z', 'X'):
            return False
    return True


def await_stopped(expected, timeout=2, clock=time.monotonic, sleep=time.sleep,
                  check=stopped, group_check=group_stopped):
    deadline = clock() + timeout
    consecutive = 0
    while clock() < deadline:
        ok = all(check(p) for p in expected)
        ok = ok and all(group_check(g) for g in {p['pgrp'] for p in expected})
        consecutive = consecutive + 1 if ok else 0
        if consecutive == 2:
            return
        sleep(.02)
    raise TimeoutError('process_or_group_not_confirmed_stopped')
