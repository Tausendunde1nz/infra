import json
import unittest
from unittest.mock import patch
import tu1nz_backup_notify_semantic_v7 as r

class ReaderTests(unittest.TestCase):
    def test_dot_and_source(self):
        for word in ('.','source'):
            result=r.summarize((word+' '+r.ENV_PATH).encode())
            self.assertIn('ENV_SHELL_SOURCE_PRESENT',result['findings'])
    def test_literal_echo_not_source(self):
        self.assertNotIn('ENV_SHELL_SOURCE_PRESENT',r.summarize(('echo source '+r.ENV_PATH).encode())['findings'])
    def test_dynamic_source_fail_closed(self):
        x=r.summarize(b'. "$ENV_FILE"')
        self.assertIn('DYNAMIC_SOURCE_REQUIRES_REVIEW',x['findings']);self.assertEqual(x['status'],'REVIEW_REQUIRED')
    def test_eval(self):
        self.assertIn('EVAL_PRESENT',r.summarize(b'eval "$DATA"')['findings'])
    def test_parser_not_automatically_safe(self):
        self.assertFalse(r.summarize(b'python3 parser.py')['safe_parser_proved'])
    def test_never_claims_caller(self):
        self.assertFalse(r.summarize(b'true')['active_caller_proved'])
    def test_secrets_suppressed(self):
        secret='CANARY-secret-value-very-private'
        x=('TOKEN='+secret+'\ncurl "https://example.invalid/'+secret+'"\ncat /private/'+secret+'\necho "'+secret+'"\n')
        self.assertNotIn(secret,json.dumps(r.summarize(x.encode())))
    def test_unclosed_quote(self):
        self.assertIn('LEXICAL_PARSE_ERROR',r.summarize(b'echo "secret')['findings'])
    def test_limit(self):
        with self.assertRaises(ValueError):r.summarize(b'x'*131073)
    def test_nonutf8(self):
        with self.assertRaises(UnicodeError):r.summarize(b'\xff')
    def test_substitution(self):
        self.assertIn('COMMAND_SUBSTITUTION_REQUIRES_REVIEW',r.summarize(b'X=$(cat /unknown)')['findings'])
    def test_nonroot_never_reads(self):
        with patch.object(r.os,'geteuid',return_value=1001),patch.object(r,'read_fixed') as rd:
            self.assertEqual(r.main(),77);rd.assert_not_called()
    def test_error_only_class(self):
        with patch.object(r.os,'geteuid',return_value=0),patch.object(r.sys,'argv',['reader']),patch.object(r.os.environ,'clear'),patch.object(r,'read_fixed',side_effect=ValueError('SECRET')),patch('builtins.print') as pr:
            self.assertEqual(r.main(),2);self.assertNotIn('SECRET',str(pr.call_args))

class FixedSourceTests(unittest.TestCase):
    def exercise(self, *, content=b'echo ok', expected=None, mode=0o100600, uid=0, nlink=1, drift=False, xattrs=()):
        import io
        import hashlib
        from types import SimpleNamespace
        directory=SimpleNamespace(st_mode=0o40700,st_uid=0)
        fields=dict(st_dev=1,st_ino=2,st_mode=mode,st_uid=uid,st_gid=0,st_nlink=nlink,
                    st_size=len(content),st_mtime_ns=1,st_ctime_ns=1)
        f=SimpleNamespace(**fields);after=SimpleNamespace(**dict(fields,st_mtime_ns=2)) if drift else f
        class Stream(io.BytesIO):
            def fileno(self):return 42
        def lstat(path):return f if path==r.SOURCE else directory
        def attrs(path):return list(xattrs) if path==r.SOURCE else []
        with patch.object(r.Path,'lstat',lstat),patch.object(r.os,'listxattr',attrs,create=True),patch.object(r.os,'open',return_value=42) as op,patch.object(r.os,'fdopen',return_value=Stream(content)),patch.object(r.os,'fstat',side_effect=[f,after]),patch.object(r,'EXPECTED',expected or hashlib.sha256(content).hexdigest()):
            result=r.read_fixed();self.assertEqual(op.call_count,1);self.assertEqual(op.call_args.args[0],r.SOURCE);return result
    def test_exact_source_only(self):self.assertEqual(self.exercise(),b'echo ok')
    def test_hash_drift(self):
        with self.assertRaises(ValueError):self.exercise(expected='0'*64)
    def test_symlink(self):
        with self.assertRaises(ValueError):self.exercise(mode=0o120600)
    def test_untrusted_owner(self):
        with self.assertRaises(ValueError):self.exercise(uid=1001)
    def test_group_read(self):
        with self.assertRaises(ValueError):self.exercise(mode=0o100640)
    def test_hardlink(self):
        with self.assertRaises(ValueError):self.exercise(nlink=2)
    def test_changed_during_read(self):
        with self.assertRaises(ValueError):self.exercise(drift=True)
    def test_source_acl(self):
        with self.assertRaises(ValueError):self.exercise(xattrs=('system.posix_acl_access',))
