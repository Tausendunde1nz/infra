"""Process-local FD admission before any historical protection or content read.

The census is capacity planning, NOT integrity acceptance. R4 witnesses still
hold all inputs together; growth, unstable inputs and exhaustion deny capture.
Only the caller's soft RLIMIT_NOFILE changes, never its hard/global limits.
"""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import resource
import stat
import threading
import time

import tu1nz_s8_execution_contract as c

CENSUS_SECONDS = 5
MAX_NODES_PER_GIT = 65536
MAX_PACKS_PER_GIT = 64  # same bound as historical_objects.ObjectStore
# At most one transient metadata/proc/directory handle per synchronous call.
# Reserve four for initialization/observer/error bookkeeping, plus four for
# cleanup/readback even after a partially built capture: no arbitrary bulk cap.
TRANSIENT_RESERVE = 8


def descriptors():
    """Snapshot actual held FD slots; omit only our own short enumeration FD."""
    fd = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        values = {}
        vanished = []
        for text in os.listdir(fd):
            c.require(text.isdigit(), 'FD_SNAPSHOT_UNAVAILABLE')
            number = int(text)
            if number == fd:
                continue
            try:
                m = os.fstat(number)
            except OSError as error:
                if error.errno != errno.EBADF: raise
                # CPython listdir(fd) duplicates/then closes one enumeration FD.
                # Any additional vanished handle is an unstable snapshot.
                vanished.append(number)
                continue
            values[number] = (m.st_dev, m.st_ino, m.st_mode, m.st_rdev)
        c.require(len(vanished) <= 1, 'FD_SNAPSHOT_UNAVAILABLE')
        return values
    finally:
        os.close(fd)


def census(roots):
    deadline = time.monotonic() + CENSUS_SECONDS
    result = []
    for root in roots:
        root = Path(root) / '.git.s12-1-recovery'
        pending = [root]
        count = packs = 0
        while pending:
            c.require(time.monotonic() < deadline and count < MAX_NODES_PER_GIT,
                      'FD_CENSUS_BOUND')
            path = pending.pop()
            before = path.lstat()
            c.require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode),
                      'FD_CENSUS_UNSAFE_OBJECT')
            count += 1
            if path.parent == root / 'objects/pack' and path.suffix == '.idx':
                packs += 1
                c.require(packs <= MAX_PACKS_PER_GIT, 'FD_PACK_BOUND')
            if stat.S_ISDIR(before.st_mode):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd)), 'FD_CENSUS_CHANGED')
                    names = os.listdir(fd)
                    c.require(count + len(pending) + len(names) <= MAX_NODES_PER_GIT,
                              'FD_CENSUS_BOUND')
                    pending.extend(path / name for name in names)
                    c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd))
                              == c.fingerprint(path.lstat()), 'FD_CENSUS_CHANGED')
                finally:
                    os.close(fd)
        result.append(dict(nodes=count, pack_indexes=packs))
    return result


def requirements(roots, history, file_count, marker_count, inventory, held):
    c.require(len(roots) == len(inventory) == 2 and file_count == 4 and marker_count == 5,
              'FD_SCOPE_RED')
    c.require(type(held) is dict and all(type(k) is int and k >= 0 for k in held), 'FD_SNAPSHOT_UNAVAILABLE')
    c.require(all(type(r) is dict and set(r) == {'nodes','pack_indexes'} and
                  type(r['nodes']) is int and 0 < r['nodes'] <= MAX_NODES_PER_GIT and
                  type(r['pack_indexes']) is int and 0 <= r['pack_indexes'] <= MAX_PACKS_PER_GIT
                  for r in inventory), 'FD_CENSUS_BOUND')
    # PathChain: one FD per ancestor including '/' and the directory itself,
    # plus its inotify FD. Duplicate ancestry stays held, not deduplicated.
    chain_cost = lambda directory: len(Path(directory).parents) + 2
    ancestry = (file_count + marker_count) * chain_cost(history)
    ancestry += sum(chain_cost(root) + chain_cost(Path(root)/'.git.s12-1-recovery') for root in roots)
    parts = dict(git_inputs=sum(r['nodes'] for r in inventory), ancestry=ancestry,
                 evidence=file_count, evidence_lease_watches=file_count,
                 git_lease_and_namespace_watches=2*len(roots),
                 # Only one ObjectStore is open at a time; CPython mmap may
                 # duplicate the index and pack FD once each, at most64 pairs.
                 pack_mapping_fds=2*max(r['pack_indexes'] for r in inventory),
                 transient_and_cleanup_reserve=TRANSIENT_RESERVE)
    # RLIMIT is highest possible FD number + 1, not merely occupied count.
    # High/sparse already-held FD numbers must not understate the needed bound.
    baseline = max(held, default=-1) + 1
    return dict(required_soft=baseline+sum(parts.values()), held_count=len(held),
                held_high_water=baseline, breakdown=parts, inventory=inventory)


def probe(roots, history, file_count=4, marker_count=5):
    c.require(os.uname().sysname == 'Linux' and len(os.listdir('/proc/self/task')) == 1,
              'FD_DEDICATED_PROCESS_REQUIRED')
    owner = (os.getpid(), threading.get_native_id())
    held = descriptors()
    inventory = census(roots)
    c.require(descriptors() == held and owner == (os.getpid(), threading.get_native_id()),
              'FD_CONTEXT_CHANGED')
    value = requirements(roots, history, file_count, marker_count, inventory, held)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    c.require(hard == resource.RLIM_INFINITY or hard >= value['required_soft'], 'FD_HARD_CAPACITY_INSUFFICIENT')
    value.update(previous_soft=soft, unchanged_hard=hard,
                 requested_soft=value['required_soft'] if soft != resource.RLIM_INFINITY
                    and soft < value['required_soft'] else soft,
                 soft_change_required=soft != resource.RLIM_INFINITY and soft < value['required_soft'],
                 process_local_only=True, hard_changed=False, census_is_integrity_proof=False)
    return value, held


class Capacity:
    def __init__(self, roots, history):
        self.value, self.held = probe(roots, history)
        self.owner = (os.getpid(), threading.get_native_id())
        self.old = (self.value['previous_soft'], self.value['unchanged_hard'])
        self.closed = False
        self.changed = self.value['soft_change_required']
        try:
            if self.changed:
                resource.setrlimit(resource.RLIMIT_NOFILE,
                                   (self.value['required_soft'], self.old[1]))
            actual = resource.getrlimit(resource.RLIMIT_NOFILE)
            c.require(actual[1] == self.old[1] and (actual[0] == resource.RLIM_INFINITY
                      or actual[0] >= self.value['required_soft']), 'FD_LIMIT_READBACK_RED')
            self.value['admitted_soft'] = actual[0]
        except BaseException as error:
            c.close_preserving(error, self)
            raise

    def observe(self):
        """Actual fully held aggregate sample, not a claim about past peaks."""
        c.require(not self.closed and self.owner == (os.getpid(), threading.get_native_id()), 'FD_CONTEXT_CHANGED')
        held = descriptors()
        c.require(all(held.get(fd) == value for fd, value in self.held.items()), 'FD_BASELINE_CHANGED')
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        c.require((soft, hard) == (self.value['admitted_soft'], self.old[1]), 'FD_CONTEXT_CHANGED')
        self.value.update(observed_common_capture_fds=len(held),
                          observed_common_capture_high_water=max(held, default=-1)+1)

    def close(self):
        c.require(not self.closed and self.owner == (os.getpid(),threading.get_native_id()), 'FD_CONTEXT_CHANGED')
        self.closed = True
        errors = []
        try:
            c.require(descriptors() == self.held, 'FD_CAPTURE_LEAK_OR_BASELINE_CHANGED')
            self.value['fd_baseline_restored'] = True
        except BaseException as error:
            errors.append(c.failure_record(error))
        try:
            if self.changed:
                resource.setrlimit(resource.RLIMIT_NOFILE, self.old)
            c.require(resource.getrlimit(resource.RLIMIT_NOFILE) == self.old, 'FD_LIMIT_RESTORE_RED')
            self.value['limit_restored'] = True
        except BaseException as error:
            errors.append(c.failure_record(error))
        if errors:
            error = c.ContractError('S8_EXECUTION_FD_CLEANUP_RED')
            error._s8_cleanup_errors = errors
            raise error


@contextmanager
def capture_capacity(roots, history, evidence=None):
    c.require(evidence is None or type(evidence) is dict, 'FD_EVIDENCE_RED')
    resource_scope = Capacity(roots, history)
    if evidence is not None:
        evidence.update(resource_scope.value)
    try:
        yield resource_scope
    except BaseException as error:
        c.close_preserving(error, resource_scope)
        if evidence is not None: evidence.update(resource_scope.value)
        raise
    else:
        try: resource_scope.close()
        finally:
            if evidence is not None: evidence.update(resource_scope.value)
