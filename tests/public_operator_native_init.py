"""Fresh disposable public-operator fixture, not a Host maintenance program.

Disable automatic DB maintenance BEFORE first PID1/postgres start in this new
synthetic cluster. Unknown-actor admission remains unchanged and is tested by
the explicit real-process fault case. No current production DB is touched.
"""
import os
from pathlib import Path
import sys

sys.path.insert(0,'/')
from s8_native_init import prepare


def main():
    assert os.getpid()==1 and os.geteuid()==0 and os.environ.get('container')=='docker'
    assert Path('/.dockerenv').is_file()
    assert not Path('/proc/net/route').read_text().splitlines()[1:]
    config=Path('/etc/postgresql/16/main/postgresql.conf')
    assert b"include_dir = 'conf.d'" in config.read_bytes()
    target=config.parent/'conf.d/00-tu1nz-synthetic-no-autovacuum.conf'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as stream:
        stream.write(b'# Synthetic source fixture only; never a Host setting.\nautovacuum = off\n')
        stream.flush();os.fsync(stream.fileno())
    prepare()  # Existing private-root/private-/run/PID1 checks remain unchanged.


if __name__=='__main__':main()
