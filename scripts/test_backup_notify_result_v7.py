import unittest
from tu1nz_backup_notify_result_v7 import *
class ReviewTests(unittest.TestCase):
    def fixture(self):return dict(reader_sha256=READER,ssh_returncode=0,result=dict(source_sha256=SOURCE,statement_shapes=[dict(line=22,parse_error=True),dict(line=23,parse_error=True),dict(line=29,parse_error=True)],findings=['LEXICAL_PARSE_ERROR'],active_caller_proved=False,safe_parser_proved=False))
    def test_real_failure_shape(self):
        r=review(self.fixture());self.assertEqual(r['parse_error_lines'],[22,23,29]);self.assertFalse(r['activation_ready'])
    def test_no_parse_error_still_not_caller_proof(self):
        f=self.fixture();f['result']['statement_shapes']=[];self.assertEqual(review(f)['caller_status'],'NOT_PROVED')
    def test_wrong_reader(self):
        f=self.fixture();f['reader_sha256']='0'*64
        with self.assertRaises(ValueError):review(f)
    def test_wrong_source(self):
        f=self.fixture();f['result']['source_sha256']='0'*64
        with self.assertRaises(ValueError):review(f)
    def test_nonzero_exit(self):
        f=self.fixture();f['ssh_returncode']=2
        with self.assertRaises(ValueError):review(f)
