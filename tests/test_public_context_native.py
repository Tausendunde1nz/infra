"""Owned synthetic kernel fixtures, ONLY the separately approved CI guest.

Mac/ordinary test discovery skips this suite. The private CI entry must demand
the exact test count and ZERO skips. Nothing here is a production Host reader.
"""
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator_context as context
import tu1nz_public_operator_io as io
import tu1nz_public_operator_observe as observe
import tu1nz_public_operator_runtime_guard as guard


def guest():
    return (sys.platform == 'linux' and os.geteuid() == 0 and
            os.environ.get('TU1NZ_CONTEXT_NATIVE') == '1' and os.environ.get('container') == 'docker' and
            Path('/proc/1/comm').read_text().strip() == 'systemd')


def checked(ok):
    if not ok:
        error=AssertionError('SYNTHETIC_CONTEXT_NATIVE_SETUP_FAILED')
        error.primary=context.NATIVE_FIXTURE_FAILED
        error.native_errno=ctypes.get_errno()
        raise error


@contextlib.contextmanager
def foreign_root(*, overlay=False, executable=False):
    """Only a forked fixture changes its OWN private mount namespace/root."""
    with tempfile.TemporaryDirectory(prefix='owned-context-native-') as folder:
        parent,child=socket.socketpair(); pid=os.fork()
        if pid == 0:
            parent.close()
            task=None;finish=threading.Event()
            try:
                libc=ctypes.CDLL(None,use_errno=True)
                checked(libc.unshare(0x00020000)==0)  # CLONE_NEWNS
                checked(libc.mount(None,b'/',None,0x40000|0x4000,None)==0)  # REC|PRIVATE
                checked(libc.mount(b'tmpfs',os.fsencode(folder),b'tmpfs',0,b'mode=0755')==0)
                base=Path(folder)
                for name in ('lower','upper','work','merged'):(base/name).mkdir(mode=0o755)
                lower=base/'lower';(lower/'usr').mkdir(mode=0o755);(lower/'usr/lib').mkdir(mode=0o755)
                (lower/'usr/lib/synthetic').write_bytes(b'SYNTHETIC_CONTEXT_CODE_NOT_HOST_SOURCE\n')
                (lower/'usr/lib/other').write_bytes(b'SYNTHETIC_ALTERNATE_INODE\n')
                (lower/'link').symlink_to('/usr/lib/synthetic')
                code_paths=['/usr/lib/synthetic']
                if executable:
                    arch=os.uname().machine
                    checked(arch in ('x86_64','aarch64'))
                    triplet='x86_64-linux-gnu' if arch=='x86_64' else 'aarch64-linux-gnu'
                    loader='/lib64/ld-linux-x86-64.so.2' if arch=='x86_64' else '/lib/ld-linux-aarch64.so.1'
                    code_paths += ['/usr/bin/dash',loader,'/lib/'+triplet+'/libc.so.6']
                    for path in code_paths[1:]:
                        target=lower/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(path,target);target.chmod(0o755)
                if overlay:
                    options=('lowerdir='+str(lower)+',upperdir='+str(base/'upper')+',workdir='+str(base/'work')).encode()
                    checked(libc.mount(b'overlay',os.fsencode(base/'merged'),b'overlay',0,options)==0)
                    root=base/'merged'
                else:root=lower
                os.chroot(root);os.chdir('/')
                if executable:
                    os.dup2(child.fileno(),0);os.dup2(child.fileno(),1)
                    os.execv('/usr/bin/dash',['/usr/bin/dash','-c',
                        'printf R; read x; exec /usr/bin/dash -c "printf E; read x"'])
                child.sendall(b'R')
                while True:
                    action=child.recv(1)
                    if action in (b'',b'Q'):break
                    if action==b'M':
                        checked(libc.mount(b'/usr/lib/other',b'/usr/lib/synthetic',None,4096,None)==0)
                        checked(libc.umount2(b'/usr/lib/synthetic',0)==0)
                    elif action==b'N':
                        os.rename('/usr/lib/synthetic','/usr/lib/returned')
                        os.rename('/usr/lib/returned','/usr/lib/synthetic')
                    elif action==b'A':
                        os.unlink('/link');os.symlink('/usr/lib/other','/link')
                    elif action==b'T':
                        def split_root():
                            try:
                                checked(libc.unshare(0x200)==0)  # only OWN task fs_struct
                                os.chroot('/usr');os.chdir('/');child.sendall(b'D')
                                checked(finish.wait(8))
                            except BaseException:child.sendall(b'F')
                        task=threading.Thread(target=split_root);task.start();continue
                    else:raise AssertionError('SYNTHETIC_CONTEXT_ACTION_UNKNOWN')
                    child.sendall(b'D')
            except BaseException:
                child.sendall(b'F');os._exit(92)
            finally:
                finish.set()
                if task is not None:task.join(timeout=2)
                child.close()
            os._exit(0)
        child.close();parent.settimeout(8); deadline=time.monotonic()+20; primary=None
        try:
            checked(parent.recv(1)==b'R')
            path='/proc/'+str(pid)+'/root'
            fd=os.open(path,context.READ|os.O_DIRECTORY)
            try:identity=context.fd_identity(fd,deadline=deadline)
            finally:os.close(fd)
            def meta(name, directory=False):
                fd=os.open(path+name,context.READ|(os.O_DIRECTORY if directory else 0))
                try:return context.file_metadata(fd)
                finally:os.close(fd)
            code_paths=['/usr/lib/synthetic']
            if executable:
                arch=os.uname().machine;triplet='x86_64-linux-gnu' if arch=='x86_64' else 'aarch64-linux-gnu'
                code_paths += ['/usr/bin/dash','/lib64/ld-linux-x86-64.so.2' if arch=='x86_64'
                               else '/lib/ld-linux-aarch64.so.1','/lib/'+triplet+'/libc.so.6']
            directories={'/'}
            for name in code_paths:
                directories.update(str(p) for p in Path(name).parents)
            names={n:dict(kind='directory',**meta(n,True)) for n in directories}
            names['/link']=dict(kind='link',uid=0,gid=0,mode=0o777,attrs={},target='/usr/lib/synthetic')
            files={p:dict(sha256=hashlib.sha256(context.read_proc(path+p,context.MAX_FILE,deadline=deadline)).hexdigest(),
                          origin_sha256='0'*64,**meta(p)) for p in code_paths}
            row=dict(anchor_pid=pid,kind='container',root_identity=identity,
                namespaces={n:os.readlink('/proc/'+str(pid)+'/ns/'+n) for n in context.NS},
                uid_map=context.read_proc('/proc/'+str(pid)+'/uid_map',deadline=deadline).decode().split(),
                gid_map=context.read_proc('/proc/'+str(pid)+'/gid_map',deadline=deadline).decode().split(),
                setgroups=context.read_proc('/proc/'+str(pid)+'/setgroups',deadline=deadline).decode().strip(),
                code_inputs=dict(files=files,names=names,
                    aliases={'/link':'/usr/lib/synthetic'},mountinfo_sha256=hashlib.sha256(
                        context.read_proc('/proc/'+str(pid)+'/mountinfo',deadline=deadline)).hexdigest()))
            yield pid,row,parent
        except BaseException as error:
            primary=error
            raise
        finally:
            try:parent.sendall(b'Q\n' if executable else b'Q')
            except OSError:pass
            parent.close();deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                found,status=os.waitpid(pid,os.WNOHANG)
                if found:
                    if primary is None:checked(os.waitstatus_to_exitcode(status)==0)
                    break
                time.sleep(.01)
            else:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
                if primary is None:raise AssertionError('SYNTHETIC_CONTEXT_CHILD_CLEANUP_TIMEOUT')
                primary.cleanup='SYNTHETIC_CONTEXT_CHILD_CLEANUP_TIMEOUT'


@unittest.skipUnless(guest(),'requires the exact approved isolated context-native guest')
class ContextNative(unittest.TestCase):
    def test_real_nonleader_private_fs_root_is_not_leader_root(self):
        with foreign_root() as (pid,row,channel):
            obj=context.ContextBindings.__new__(context.ContextBindings);obj.deadline=time.monotonic()+10
            self.assertEqual(len(obj.task_roots(pid,row['root_identity'])),1)
            channel.sendall(b'T');self.assertEqual(channel.recv(1),b'D')
            with self.assertRaisesRegex(io.Hold,'TASK_ROOT_DRIFT'):obj.task_roots(pid,row['root_identity'])

    def executable_case(self, overlay):
        with foreign_root(overlay=overlay,executable=True) as (pid,row,channel):
            deadline=time.monotonic()+10;epoch=context.ExecEpoch({pid},deadline);root=None
            try:
                root=context.RootBindings(row,deadline,epoch);root.check()
                fd=os.open('/proc/'+str(pid)+'/exe',context.READ)
                try:self.assertEqual(context.fd_identity(fd,deadline=deadline),
                    context.fd_identity(root.files['/usr/bin/dash'][0],deadline=deadline))
                finally:os.close(fd)
                tick=observe.starttime(pid)
                channel.sendall(b'E\n');self.assertEqual(channel.recv(1),b'E')
                self.assertEqual(observe.starttime(pid),tick)
                with self.assertRaisesRegex(io.Hold,'EXEC_EVENT_OR_VIEW_UNKNOWN'):root.check()
            finally:
                if root is not None:root.close(check=False)
                epoch.close()

    def test_foreign_root_real_exe_and_same_image_exec(self):self.executable_case(False)

    def test_overlay_root_real_exe_and_same_image_exec(self):self.executable_case(True)

    def root_case(self, *, overlay=False, action=None):
        with foreign_root(overlay=overlay) as (pid,row,channel):
            epoch=context.ExecEpoch({pid},time.monotonic()+10);root=None
            try:
                root=context.RootBindings(row,time.monotonic()+10,epoch);root.check()
                self.assertEqual(root.pin('/link'),'/usr/lib/synthetic')
                if action:
                    channel.sendall(action);self.assertEqual(channel.recv(1),b'D')
                    with self.assertRaises(io.Hold):root.check()
                    with self.assertRaises(io.Hold):root.check()  # no acknowledgement/reset
            finally:
                if root is not None:root.close(check=False)
                epoch.close()

    def test_foreign_root_absolute_alias_positive(self):self.root_case()

    def test_overlay_root_positive(self):self.root_case(overlay=True)

    def test_foreign_overmount_and_return_is_latched(self):self.root_case(action=b'M')

    def test_overlay_overmount_and_return_is_latched(self):self.root_case(overlay=True,action=b'M')

    def test_rename_and_return_is_latched(self):self.root_case(action=b'N')

    def test_alias_retarget_is_latched(self):self.root_case(action=b'A')

    def test_same_image_exec_has_real_passive_notification(self):
        program='import os;os.write(1,b"R");os.read(0,1);os.execv("/usr/bin/python3",["/usr/bin/python3","-I","-B","-c","import os;os.write(1,b\\\"E\\\");os.read(0,1)"])'
        child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',program],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin','LC_ALL':'C'})
        epoch=None
        try:
            self.assertEqual(child.stdout.read(1),b'R');tick=observe.starttime(child.pid)
            epoch=context.ExecEpoch({child.pid},time.monotonic()+10)
            fd=os.open('/proc/'+str(child.pid)+'/exe',context.READ)
            try:epoch.mark(fd)
            finally:os.close(fd)
            child.stdin.write(b'E');child.stdin.flush();self.assertEqual(child.stdout.read(1),b'E')
            self.assertEqual(observe.starttime(child.pid),tick)
            with self.assertRaisesRegex(io.Hold,'EXEC_EVENT_OR_VIEW_UNKNOWN'):epoch.check()
        finally:
            if epoch is not None:epoch.close()
            child.stdin.close();child.wait(timeout=8);child.stdout.close()

    def test_real_pidfd_duplicate_unix_getters_preserve_shared_flags(self):
        library=ctypes.CDLL(None,use_errno=True)
        with tempfile.TemporaryDirectory(prefix='owned-context-unix-') as folder:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);pair=socket.socketpair();pidfd=os.pidfd_open(os.getpid(),0)
            try:
                listener.bind(folder+'/synthetic.sock');listener.listen(1)
                for stream,kind in ((listener,'listener'),(pair[0],'connected')):
                    before=os.get_blocking(stream.fileno());copy=library.syscall(438,pidfd,stream.fileno(),0)
                    self.assertGreaterEqual(copy,0)
                    try:
                        observed=context.unix_descriptor(library,copy)
                        self.assertEqual(observed['kind'],kind)
                        self.assertEqual(os.get_blocking(stream.fileno()),before)
                        if kind=='connected':
                            row=observe.process(os.getpid());profile={'owned_synthetic_peer':True}
                            bound=context.peer_binding(library,copy,observed,{row['pid']:row},lambda r,p:True,
                                [profile],observe.process,deadline=time.monotonic()+5)
                            self.assertEqual(bound['peer_starttime'],row['starttime'])
                            with self.assertRaises(io.Hold):
                                context.peer_binding(library,copy,observed,{row['pid']:dict(row,starttime='1')},
                                    lambda r,p:True,[profile],observe.process,deadline=time.monotonic()+5)
                    finally:os.close(copy)
            finally:
                os.close(pidfd);listener.close()
                for stream in pair:stream.close()

    def test_new_code_writer_has_no_tcb_exemption(self):
        with tempfile.TemporaryDirectory(prefix='owned-context-writer-') as folder:
            path=Path(folder)/'synthetic-code';path.write_bytes(b'OWNED_SYNTHETIC_CODE')
            fd=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                value=os.fstat(fd)
                with self.assertRaisesRegex(io.Hold,'EXISTING_SOURCE_WRITABLE_FD'):
                    guard.writer_task('/proc/self/task/'+str(os.getpid()),{(value.st_dev,value.st_ino)},time.monotonic()+10)
            finally:os.close(fd)


if __name__ == '__main__':unittest.main()
