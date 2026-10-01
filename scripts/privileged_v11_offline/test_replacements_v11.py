import hashlib,unittest
from unittest.mock import patch
import replacements_v11 as r
class ReplacementTests(unittest.TestCase):
 def test_post_only_privilege_calls_change(self):
  old=b'BOT_TOKEN="FIXTURE_ONLY"\nsudo mkdir -p /opt/trendwatch\necho "${MAIN_TREND_TITLE}" | sudo tee /opt/trendwatch/today_title.txt\n'
  with patch.object(r,'POST_SHA',hashlib.sha256(old).hexdigest()):new=r.trendwatch_post(old)
  self.assertEqual(new,old.replace(b'sudo mkdir',b'mkdir').replace(b'sudo tee',b'tee'))
 def test_source_drift(self):
  with self.assertRaises(r.Refused):r.trendwatch_post(b'other')
 def test_extra_sudo_rejected(self):
  old=b'sudo mkdir -p /opt/trendwatch\nsudo tee /opt/trendwatch/today_title.txt\nsudo id'
  with patch.object(r,'POST_SHA',hashlib.sha256(old).hexdigest()):
   with self.assertRaises(r.Refused):r.trendwatch_post(old)
 def test_unit_fixed_nonroot(self):
  old=b'[Service]\nType=oneshot\nExecStart=/usr/local/bin/trendwatch_post.sh\n'
  with patch.dict(r.UNIT_SHA,{'trendwatch2-morning.service':hashlib.sha256(old).hexdigest()}):v=r.trendwatch_unit('trendwatch2-morning.service',old)
  self.assertIn('User=chatops',v);self.assertIn('NoNewPrivileges=true',v);self.assertNotIn('sudo',v)
 def test_unknown_unit(self):
  with self.assertRaises(r.Refused):r.trendwatch_unit('mychatbuddy-private-alpha.service',b'')
 def test_existing_user_refused(self):
  old=b'[Service]\nUser=other\nExecStart=/usr/local/bin/trendwatch_post.sh\n'
  with patch.dict(r.UNIT_SHA,{'trendwatch2-morning.service':hashlib.sha256(old).hexdigest()}):
   with self.assertRaises(r.Refused):r.trendwatch_unit('trendwatch2-morning.service',old)
 def test_doc_unit_nonroot(self):
  s=r.document_worker_unit();self.assertIn('User=chatops',s);self.assertIn('python3 -I -B',s);self.assertNotIn('ExecStartPost=+',s)
if __name__=='__main__':unittest.main()
