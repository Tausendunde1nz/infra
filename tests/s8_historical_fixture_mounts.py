"""Owned disposable-fixture teardown; no production mount API or retries."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

STATE = Path('/s8-provision-owned-mounts.json')


def mounts():
    def decode(value):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
    result = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        fields, tail = before.split(), after.split()
        result.append(dict(id=int(fields[0]), device=fields[2], root=decode(fields[3]),
                           target=decode(fields[4]), fstype=tail[0], source=decode(tail[1])))
    return result


def capture(target, allowed):
    target = str(target)
    rows = [v for v in mounts() if v['target'] == target]
    assert len(rows) == 1 and target in allowed, 'S8_NATIVE_FIXTURE_MOUNT_AMBIGUOUS'
    value = dict(rows[0])
    info = os.stat(target)
    value.update(namespace=os.stat('/proc/self/ns/mnt').st_ino,
                 inode=info.st_ino, st_dev=info.st_dev, allowed=sorted(map(str, allowed)))
    return value


def current(value):
    assert os.stat('/proc/self/ns/mnt').st_ino == value['namespace'], 'S8_NATIVE_FIXTURE_NAMESPACE_CHANGED'
    rows = [v for v in mounts() if v['id'] == value['id']]
    assert len(rows) == 1, 'S8_NATIVE_FIXTURE_MOUNT_MISSING'
    row = rows[0]
    assert all(row[k] == value[k] for k in ('device', 'root', 'fstype', 'source')), 'S8_NATIVE_FIXTURE_MOUNT_REPLACED'
    assert row['target'] in value['allowed'], 'S8_NATIVE_FIXTURE_TARGET_UNBOUND'
    assert sum(v['target'] == row['target'] for v in mounts()) == 1, 'S8_NATIVE_FIXTURE_TARGET_STACKED'
    info = os.stat(row['target'])
    assert (info.st_dev, info.st_ino) == (value['st_dev'], value['inode']), 'S8_NATIVE_FIXTURE_OBJECT_REPLACED'
    return row['target']


def unmount_owned(value):
    target = current(value)
    subprocess.run(['umount', '--', target], check=True, capture_output=True)
    assert not any(v['id'] == value['id'] for v in mounts()), 'S8_NATIVE_FIXTURE_UNMOUNT_UNCONFIRMED'


def release_all(values, primary_code):
    errors = []
    for value in values:
        try:
            unmount_owned(value)
        except BaseException as error:
            # Only machine codes/types, no mount or synthetic credential data.
            code = str(error)
            errors.append(dict(type=type(error).__name__,
                               code=code if re.fullmatch(r'S8_[A-Z0-9_]+', code) else 'UNKNOWN'))
    return dict(primary_code=primary_code, cleanup=errors), primary_code or (2 if errors else 0)


def main():
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0 and os.environ.get('container') == 'docker'
    mode = sys.argv[1]
    if mode == 'capture':
        assert not os.path.lexists(STATE), 'S8_NATIVE_FIXTURE_STATE_ALREADY_EXISTS'
        history = '/etc/tu1nz/adult-commercial-s12-1-private/state'
        retained = '/etc/tu1nz-native-retained-parent/adult-commercial-s12-1-private/state'
        values = [capture(history, (history, retained)),
                  capture('/opt/tu1nz_repos', ('/opt/tu1nz_repos',)),
                  capture('/s8-provision-historical', ('/s8-provision-historical',))]
        assert all(v['fstype'] == 'ext4' and v['device'] == values[-1]['device']
                   and v['source'] == values[-1]['source'] for v in values)
        with STATE.open('x') as stream:
            json.dump(values, stream, sort_keys=True)
    elif mode == 'release':
        values = json.loads(STATE.read_bytes())
        result, status = release_all(values, int(sys.argv[2]))
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(status)
    else:
        raise AssertionError('S8_NATIVE_FIXTURE_MODE_UNKNOWN')


if __name__ == '__main__':
    main()
