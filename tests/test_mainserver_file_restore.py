"""Private synthetic Mac restore tests; real-data/foreign-Owner gates stay open."""
import copy
import ctypes
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('file_restore',Path(__file__).resolve().parents[1]/
                                          'scripts/tu1nz_mainserver_file_restore.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    raw=b'SYNTHETIC file restore, no production information\n';digest=m.sha(raw)
    common=dict(device=1,inode=10,uid=os.geteuid(),gid=os.getegid(),mode=0o644,type=stat.S_IFREG,
                nlink=1,size=len(raw),mtime_ns=1760000000123456789,ctime_ns=1760000000133456789,
                atime_ns=1760000000123456789,attrs={},flags=0x80000)
    d=dict(common,type=stat.S_IFDIR,mode=0o755,inode=9,nlink=2,size=4096)
    manifest={'/var/www/lighting.tu1nz.com':{'sha256':None,'metadata':d},
              '/var/www/lighting.tu1nz.com/index.html':{'sha256':digest,'metadata':common},
              '/etc/tu1nz/example.json':{'sha256':digest,'metadata':dict(common,inode=11)}}
    return manifest,{digest:raw},sorted(manifest)


class Profile(unittest.TestCase):
    def test_actual_bytes_and_exact_paths_required_before_any_creation(self):
        a,b,c=fixture();self.assertEqual(m.profile(a,b,c),2*len(next(iter(b.values()))))
        for aa,bb,cc in ((a,{},c),(a,b,c[:-1]),(a,b,c+c[:1]),
                         (a,{**b,'0'*64:b'not bound'},c)):
            with self.assertRaises(m.Denied):m.profile(aa,bb,cc)

    def test_acl_xattr_flags_links_special_files_privilege_are_not_downgraded(self):
        for key,value in (('attrs',{'system.posix_acl_access':'AAAA'}),('attrs',{'user.x':'AAAA'}),
                          ('flags',0x10),('type',stat.S_IFLNK),('type',stat.S_IFIFO),('nlink',2),
                          ('mode',0o4755),('mode',0o755),('uid',True)):
            a,b,c=fixture();a[c[0]]['metadata'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(m.Denied):m.profile(a,b,c)

    def test_path_escape_and_regular_file_parent_deny(self):
        for bad in ('../escape','/a/../escape','//escape','/a//escape','/a/./escape','/a/space name'):
            a,b,c=fixture();a[bad]=a.pop(c[0])
            with self.subTest(path=bad),self.assertRaises(m.Denied):m.profile(a,b,sorted(a))
        a,b,c=fixture();a['/etc/tu1nz/example.json/child']=copy.deepcopy(a[c[0]])
        with self.assertRaises(m.Denied):m.profile(a,b,sorted(a))

    def test_mutated_backup_and_missing_metadata_deny(self):
        a,b,c=fixture();b[next(iter(b))]+=b'changed'
        with self.assertRaises(m.Denied):m.profile(a,b,c)
        a,b,c=fixture();del a[c[0]]['metadata']['mtime_ns']
        with self.assertRaises(m.Denied):m.profile(a,b,c)


@unittest.skipUnless(sys.platform=='darwin' and os.geteuid()==0,
                     'requires personally authenticated local root; no privilege emulation')
class NativeMacRestore(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name).resolve()
        self.fd=os.open(self.path,m.OPEN|os.O_DIRECTORY)
    def tearDown(self):
        os.close(self.fd);self.temp.cleanup()
    def test_actual_copy_metadata_rename_cleanup_and_no_reentry(self):
        a,b,c=fixture();proof=m.restore_private_files(self.fd,a,b,c,deadline=time.monotonic()+10)
        self.assertEqual(proof['objects'],3);self.assertTrue(proof['own_test_cleanup'])
        self.assertEqual(os.listdir(self.path/'file-restore'),[])
        self.assertEqual(stat.S_IMODE((self.path/'file-restore').stat().st_mode),0o700)
        for path in c:
            row=proof['observations'][path]
            self.assertEqual(row['mtime_ns'],a[path]['metadata']['mtime_ns'])
            self.assertEqual(row['uid'],os.geteuid())
            self.assertNotEqual(row['inode'],a[path]['metadata']['inode'])
        with self.assertRaises(FileExistsError):m.restore_private_files(self.fd,a,b,c,deadline=time.monotonic()+10)
    def test_unknown_xattr_or_acl_is_rejected_and_never_stripped(self):
        native=m.NativeMac();native.plain(self.fd)
        subprocess.run(['/usr/bin/xattr','-w','user.tu1nz-synthetic','synthetic',str(self.path)],check=True)
        with self.assertRaises(m.Denied):native.plain(self.fd)
        self.assertGreater(native.lib.flistxattr(self.fd,None,0,0),0)
        subprocess.run(['/usr/bin/xattr','-d','user.tu1nz-synthetic',str(self.path)],check=True)
        subprocess.run(['/bin/chmod','+a','everyone deny delete',str(self.path)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(m.Denied,'ACL_NOT_EMPTY'):native.plain(self.fd)
        finally:
            subprocess.run(['/bin/chmod','-a','everyone deny delete',str(self.path)],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def test_input_denial_or_deadline_never_creates_restore_tree(self):
        a,b,c=fixture()
        with self.assertRaises(m.Denied):m.restore_private_files(self.fd,a,{},c,deadline=time.monotonic()+10)
        with self.assertRaises(m.Denied):m.restore_private_files(self.fd,a,b,c,deadline=time.monotonic()-1)
        self.assertEqual(os.listdir(self.fd),[])
    def test_symlink_at_fixed_entry_is_not_followed(self):
        (self.path/'file-restore').symlink_to(self.path)
        a,b,c=fixture()
        with self.assertRaises(FileExistsError):m.restore_private_files(self.fd,a,b,c,deadline=time.monotonic()+10)
        self.assertEqual(os.listdir(self.fd),['file-restore'])
    def test_foreign_file_during_cleanup_is_retained_and_cannot_pass(self):
        original=m.NativeMac.rename
        def inject(native,fd,source,target):
            original(native,fd,source,target)
            if target==b'tree':
                child=os.open('tree',m.OPEN|os.O_DIRECTORY,dir_fd=fd)
                try:
                    f=os.open('unbound',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=child);os.close(f)
                finally:os.close(child)
        a,b,c=fixture()
        with patch.object(m.NativeMac,'rename',inject),self.assertRaisesRegex(m.Denied,'CLEANUP_FOREIGN_ENTRY'):
            m.restore_private_files(self.fd,a,b,c,deadline=time.monotonic()+10)
        self.assertTrue((self.path/'file-restore/tree/unbound').exists())
    def test_exclusive_rename_does_not_replace_existing_target(self):
        os.mkdir('a',dir_fd=self.fd);os.mkdir('b',dir_fd=self.fd)
        with self.assertRaises(m.Denied):m.NativeMac().rename(self.fd,b'a',b'b')
        self.assertEqual(set(os.listdir(self.fd)),{'a','b'})


if __name__=='__main__':unittest.main()
