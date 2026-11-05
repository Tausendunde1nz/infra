"""Synthetic boundary tests; no real Host, DSN, database or private data."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('tu1nz_mainserver_backup');r=load('tu1nz_mainserver_restore');f=load('tu1nz_mainserver_file_restore')


class BackupBoundary(unittest.TestCase):
    def test_dsn_exact_database_role_and_destination_no_escalation(self):
        values=dict(user=m.ROLE,dbname=m.DATABASE,password='a:b\\c')
        self.assertEqual(m.passfile_bytes(values),('127.0.0.1:15432:'+m.DATABASE+':'+m.ROLE+':a\\:b\\\\c\n').encode())
        for key,value in (('user','postgres'),('host','external.example'),('dbname','another_database'),
                          ('port','6543'),('service','default'),('options','-c search_path=public'),
                          ('sslmode','verify-full'),('gssencmode','require'),('password','x\ny')):
            with self.subTest(key=key),self.assertRaises(m.Denied):m.passfile_bytes({**values,key:value})
    def test_environment_is_fixed_tls_scram_no_inherited_secret_or_rc(self):
        env=m.database_environment(Path('/private/fixture'),Path('/private/tools'))
        self.assertEqual(env['PGCHANNELBINDING'],'require');self.assertEqual(env['PGSSLMODE'],'require')
        self.assertEqual(env['PGHOST'],'127.0.0.1');self.assertEqual(env['PGPORT'],'15432')
        self.assertFalse({'PGPASSWORD','HOME','DYLD_INSERT_LIBRARIES','LD_PRELOAD'} & set(env))
        self.assertEqual(env['PGSERVICEFILE'],'/dev/null')
    def test_ssh_has_single_fixed_forward_no_agent_or_user_configuration(self):
        real=subprocess.Popen;observed=[]
        def launch(argv,**kwargs):
            observed.append(argv)
            return real([sys.executable,'-I','-B','-c',
                "import sys,json;sys.stdin.buffer.readline();sys.stdin.buffer.readline();"
                "print(json.dumps({'kind':'ready'}),flush=True);"
                "assert sys.stdin.buffer.readline()==b'REV4_BACKUP_CLOSE\\n';"
                "print(json.dumps({'kind':'closed','fds_closed':True,'host_mutations':False}),flush=True)"],**kwargs)
        secret=bytearray(b'synthetic-personal-input\n')
        with patch.object(m.subprocess,'Popen',side_effect=launch):
            ssh=m.PrivateSSH(b'def main(pin):pass\n',{'large':'x'*170000},secret,time.monotonic()+5)
        try:
            self.assertEqual(ssh.frame(),{'kind':'ready'});ssh.finish()
            self.assertEqual(secret,bytearray(len(secret)))
            argv=observed[0];self.assertEqual(argv[:4],['/usr/bin/ssh','-F','/dev/null','-T'])
            self.assertEqual(argv.count('-L'),1)
            self.assertEqual(argv[argv.index('-L')+1],'127.0.0.1:15432:127.0.0.1:5432')
            self.assertIn('ForwardAgent=no',argv);self.assertIn('ProxyCommand=none',argv)
            self.assertNotIn('ClearAllForwardings=yes',argv)
            self.assertNotIn('synthetic-personal-input',' '.join(argv))
            import shlex
            command=shlex.split(argv[-1])
            self.assertEqual(command[:10],['/usr/bin/sudo','-k','-S','-p','','--','/usr/bin/python3','-I','-B','-S'])
            self.assertNotIn('x'*170000,argv[-1]) # scope uses bounded stdin, not Linux's argv limit
        finally:ssh.close()
    def test_ssh_rejects_unknown_stderr_and_closes_its_child(self):
        real=subprocess.Popen;children=[]
        def launch(argv,**kwargs):
            child=real([sys.executable,'-I','-B','-c',
                "import sys,time;sys.stdin.buffer.readline();sys.stdin.buffer.readline();"
                "sys.stderr.write('SYNTHETIC FAILURE\\n');sys.stderr.flush();time.sleep(5)"],**kwargs)
            children.append(child);return child
        with patch.object(m.subprocess,'Popen',side_effect=launch):
            ssh=m.PrivateSSH(b'def main(pin):pass\n',{},bytearray(b'fake\n'),time.monotonic()+2)
        try:
            with self.assertRaisesRegex(m.Denied,'SSH_OR_SUDO_DIAGNOSTIC'):ssh.frame()
        finally:ssh.close()
        self.assertIsNotNone(children[0].poll())
    def test_private_input_symlink_or_mode_never_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();p=root/'receipt';p.write_bytes(b'{}');p.chmod(0o600)
            self.assertEqual(m.private_read(p,32,owner=os.geteuid()),b'{}')
            p.chmod(0o644)
            with self.assertRaisesRegex(m.Denied,'PROFILE'):m.private_read(p,32,owner=os.geteuid())
            link=root/'link';link.symlink_to(p)
            with self.assertRaisesRegex(m.Denied,'CANONICAL'):m.private_read(link,32,owner=os.geteuid())
    def test_no_review_or_host_execution_on_import(self):
        for name in m.MODULES:
            raw=(SCRIPTS/name).read_bytes();module=m.load_source(name,raw)
            self.assertIsNotNone(module)


class FileTransfer(unittest.TestCase):
    def fixture(self):
        rows={};raw=b'SYNTHETIC';digest=m.sha(raw)
        for n in range(102):
            rows['/finite/f'+str(n)]={'sha256':digest,'metadata':dict(device=1,inode=n+1,uid=0,gid=0,mode=0o600,
                type=stat.S_IFREG,nlink=1,size=len(raw),mtime_ns=1,ctime_ns=1,atime_ns=1,attrs={},flags=0)}
        scope={'reader_scope':{'files':sorted(rows),'machine_sha256':'1'*64}}
        frames=[{'kind':'file','path':p,'row':row,'content_base64':base64.b64encode(raw).decode()}
                for p,row in sorted(rows.items())]
        frames.append(dict(kind='files_complete',scope_sha256=m.sha(m.canonical(scope['reader_scope'])),
            machine_sha256='1'*64,boot_id='11111111-1111-1111-1111-111111111111',started_unix=1,finished_unix=2,
            objects=102,bytes=102*len(raw),manifest_sha256=m.sha(m.canonical(rows)),directories={},
            semantics='PER_OBJECT_STABLE_PRESTOP_COPY_NOT_GLOBAL_ATOMIC_OR_WRITER_FENCED'))
        return scope,frames
    def receive(self,scope,frames,root):
        class Channel:
            def frame(self):return frames.pop(0)
        original=m.private_read
        with patch.object(m,'private_read',side_effect=lambda p,n:original(p,n,owner=os.geteuid())):
            return m.receive_files(Channel(),scope,root,r,f)
    def test_full_readback_deduplicated_blobs_and_exact_102_members(self):
        scope,frames=self.fixture()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();root.chmod(0o700);(root/'blobs').mkdir(mode=0o700)
            rows,blobs,receipt=self.receive(scope,frames,root)
            self.assertEqual(len(rows),102);self.assertEqual(len(blobs),1);self.assertEqual(receipt['objects'],102)
            self.assertEqual(len(list((root/'blobs').iterdir())),1)
    def test_content_corruption_omission_extra_fields_and_metadata_fail(self):
        for kind in ('hash','path','field','attrs','receipt'):
            scope,frames=self.fixture()
            if kind=='hash':frames[0]['content_base64']=base64.b64encode(b'CORRUPT').decode()
            if kind=='path':frames[0]['path']='/etc/shadow'
            if kind=='field':frames[0]['extra']='unbound'
            if kind=='attrs':frames[0]['row']['metadata']['attrs']={'unknown':'AA=='}
            if kind=='receipt':frames[-1]['objects']=101
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                root=Path(d).resolve();root.chmod(0o700);(root/'blobs').mkdir(mode=0o700)
                with self.assertRaises((m.Denied,f.Denied)):self.receive(scope,frames,root)


class Cleanup(unittest.TestCase):
    def test_only_ended_owned_private_tree_removed_receipts_remain(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();root.chmod(0o700);cluster=root/'cluster';cluster.mkdir(mode=0o700)
            socket_parent=root/'socket';socket_parent.mkdir(mode=0o700);socket=socket_parent/'s';socket.mkdir(mode=0o700)
            p=cluster/'data';p.write_bytes(b'SYNTHETIC');p.chmod(0o600)
            receipt=root/'RESULT';receipt.write_bytes(b'HISTORICAL')
            class Child:
                def poll(self):return 0
            class PG:pass
            pg=PG();pg.created=True;pg.child=Child();pg.root=cluster;pg.socket=socket
            ident=lambda p:(p.stat().st_dev,p.stat().st_ino,p.stat().st_uid,p.stat().st_mode)
            pg.restore_identity=ident(cluster);pg.socket_identity=ident(socket);pg.socket_parent_identity=ident(socket_parent)
            result=m.cleanup_owned_cluster(pg,cluster)
            self.assertTrue(result['own_cluster_removed']);self.assertEqual(receipt.read_bytes(),b'HISTORICAL')
    def test_foreign_link_retains_tree(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();root.chmod(0o700);cluster=root/'cluster';cluster.mkdir(mode=0o700)
            (cluster/'unexpected').symlink_to('/etc/passwd')
            class Child:
                def poll(self):return 0
            class PG:pass
            sockets=root/'socket';sockets.mkdir(mode=0o700);sock=sockets/'s';sock.mkdir(mode=0o700)
            pg=PG();pg.created=True;pg.child=Child();pg.root=cluster;pg.socket=sock
            ident=lambda p:(p.stat().st_dev,p.stat().st_ino,p.stat().st_uid,p.stat().st_mode)
            pg.restore_identity=ident(cluster);pg.socket_identity=ident(sock);pg.socket_parent_identity=ident(sockets)
            with self.assertRaisesRegex(m.Denied,'FOREIGN_OBJECT'):m.cleanup_owned_cluster(pg,cluster)
            self.assertTrue(cluster.exists())


@unittest.skipUnless(os.geteuid()==0,'real privileged FD ownership fixture; no emulated chown')
class NewRootParent(unittest.TestCase):
    def setUp(self):
        self.entry=load('tu1nz_mainserver_file_restore_entry')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.child=self.root/'privileged-restore'
        self.child.mkdir(mode=0o700);os.chown(self.child,0,20)
        self.created=os.open(self.child,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    def tearDown(self):
        os.close(self.created);os.close(self.fd);self.tmp.cleanup()
    def test_real_gid20_inode_becomes_root_root_without_parent_change(self):
        parent=os.fstat(self.fd);before=os.fstat(self.created)
        self.assertEqual((before.st_uid,before.st_gid),(0,20))
        self.entry.bind_created_parent(self.fd,self.created)
        after=os.fstat(self.created)
        self.assertEqual((after.st_dev,after.st_ino),(before.st_dev,before.st_ino))
        self.assertEqual((after.st_uid,after.st_gid,stat.S_IMODE(after.st_mode)),(0,0,0o700))
        self.assertEqual((os.fstat(self.fd).st_uid,os.fstat(self.fd).st_gid,os.fstat(self.fd).st_mode),
                         (parent.st_uid,parent.st_gid,parent.st_mode))
    def test_swapped_name_does_not_chown_either_inode(self):
        self.child.rename(self.root/'original');self.child.mkdir(mode=0o700);os.chown(self.child,0,20)
        with self.assertRaisesRegex(RuntimeError,'NOT_BOUND'):self.entry.bind_created_parent(self.fd,self.created)
        self.assertEqual(os.fstat(self.created).st_gid,20);self.assertEqual(self.child.stat().st_gid,20)
    def test_nonroot_owned_or_wrong_mode_child_is_not_repaired(self):
        os.fchown(self.created,501,20)
        with self.assertRaisesRegex(RuntimeError,'NOT_BOUND'):self.entry.bind_created_parent(self.fd,self.created)
        self.assertEqual(os.fstat(self.created).st_uid,501)
        os.fchown(self.created,0,20);os.fchmod(self.created,0o750)
        with self.assertRaisesRegex(RuntimeError,'NOT_BOUND'):self.entry.bind_created_parent(self.fd,self.created)
        self.assertEqual(os.fstat(self.created).st_gid,20)


if __name__=='__main__':unittest.main()
