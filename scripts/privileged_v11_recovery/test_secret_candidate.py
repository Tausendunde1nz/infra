import unittest,subprocess
import trendwatch_secret_candidate as s
class SecretCandidateTests(unittest.TestCase):
 def fixture(self):
  token=str(1234567)+':'+('x'*35)
  return ('#!/bin/bash\nBOT_TOKEN="'+token+'"\nsudo mkdir -p /opt/trendwatch\nprintf x | sudo tee /opt/trendwatch/today_title.txt\ncurl -s "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" --data-urlencode "text=fixture"\n').encode()
 def test_removes_literal_and_argv_url(self):
  out=s._transform(self.fixture());self.assertNotIn(str(1234567).encode(),out);self.assertIn(b'--config -',out);self.assertIn(b'CREDENTIALS_DIRECTORY',out);self.assertNotIn(b'sudo ',out);self.assertEqual(subprocess.run(['bash','-n'],input=out,capture_output=True).returncode,0)
 def test_unbound_source_denied(self):
  with self.assertRaises(s.Refused):s.transform(self.fixture())
 def test_second_curl_denied(self):
  with self.assertRaises(s.Refused):s._transform(self.fixture()+b'curl other\n')
 def test_unknown_url_denied(self):
  with self.assertRaises(s.Refused):s._transform(self.fixture().replace(b'api.telegram.org',b'example.invalid'))
 def test_remaining_sudo_denied(self):
  with self.assertRaises(s.Refused):s._transform(self.fixture()+b'sudo true\n')
 def test_empty_or_duplicate_assignment_denied(self):
  for b in [b'#!/bin/bash\n',self.fixture()+b'BOT_TOKEN=other\n']:
   with self.assertRaises(s.Refused):s._transform(b)
 def test_secret_only_on_stdin_even_with_xtrace(self):
  import tempfile,os,json
  from pathlib import Path
  with tempfile.TemporaryDirectory() as name:
   d=Path(name);(d/'work').mkdir();token=str(1234567)+':'+('x'*35);(d/'trendwatch-token').write_text(token);(d/'trendwatch-token').chmod(0o600)
   curl=d/'curl';curl.write_text("#!/usr/bin/python3\nimport sys,json,os\ns=sys.stdin.read()\nwith open(os.environ['RESULT'],'w') as f:json.dump({'argv_clean':not any('x'*35 in a for a in sys.argv),'config_line':s.startswith('url = '+chr(34)+'https://api.telegram.org/bot') and s.endswith('/sendMessage'+chr(34)+chr(10)) and len(s.splitlines())==1},f)\n")
   curl.chmod(0o700);candidate=s._transform(self.fixture()).replace(b'/opt/trendwatch',str(d/'work').encode())
   r=subprocess.run(['bash','-x'],input=candidate,capture_output=True,env={'PATH':str(d)+':/usr/bin:/bin','CREDENTIALS_DIRECTORY':str(d),'RESULT':str(d/'result')})
   self.assertEqual(r.returncode,0);self.assertNotIn(token.encode(),r.stderr);self.assertNotIn(token.encode(),r.stdout)
   self.assertEqual(json.loads((d/'result').read_text()),{'argv_clean':True,'config_line':True})
 def test_missing_credential_fails_before_curl(self):
  r=subprocess.run(['bash'],input=s._transform(self.fixture()),capture_output=True,env={'PATH':'/usr/bin:/bin'})
  self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main()
