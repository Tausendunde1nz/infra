import fcntl,hashlib,json,os,signal,subprocess,tempfile,time,unittest
from pathlib import Path
SOURCE=Path(__file__).with_name('agentmode_observer_v11.sh')
class ObserverTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.control=self.root/'control';self.docs=self.root/'docs'
  for d in (self.control,self.docs):
   d.mkdir();self.git(d,'init','-q','-b','control-main');self.git(d,'config','user.name','fixture');self.git(d,'config','user.email','fixture@example.invalid');(d/'tracked').write_text('baseline');self.git(d,'add','tracked');self.git(d,'commit','-qm','fixture')
  self.git(self.control,'remote','add','origin',str(self.control));self.head=self.git(self.control,'rev-parse','HEAD').strip();self.git(self.control,'checkout','--detach','-q')
  self.notify=self.root/'notify.conf';self.notify.write_text('BOT_TOKEN=fixture\nALERT_CHAT_ID=fixture\n')
  self.calls=self.root/'calls';curl=self.root/'curl';curl.write_text('#!/bin/sh\ncat >/dev/null\nprintf "sent\\n" >> "$FIXTURE_CALLS"\n');curl.chmod(0o700)
  self.env={'PATH':'/usr/bin:/bin','HOME':str(self.root),'LANG':'C.UTF-8','TU1NZ_CONTROL_DIR':str(self.control),'TU1NZ_DOCS_DIR':str(self.docs),'TU1NZ_STATE_DIR':str(self.root/'state'),'TU1NZ_LOG_DIR':str(self.root/'log'),'TU1NZ_LOCK_FILE':str(self.root/'run/lock'),'TU1NZ_NOTIFY_CONFIG':str(self.notify),'TU1NZ_CURL_BIN':str(curl),'TU1NZ_EXPECTED_DETACHED_HEAD':self.head,'TU1NZ_INTERVAL_SECONDS':'60','FIXTURE_CALLS':str(self.calls)}
 def git(self,d,*args):return subprocess.check_output(['git','-C',str(d),*args],stderr=subprocess.DEVNULL,text=True)
 def run_observer(self,mode='--observe-once'):
  return subprocess.run(['/bin/bash',str(SOURCE),mode],env=self.env,capture_output=True,text=True,timeout=15)
 def fingerprint(self,d):
  return {str(p.relative_to(d)):hashlib.sha256(p.read_bytes()).hexdigest() for p in d.rglob('*') if p.is_file()}
 def test_detached_pin_passes(self):self.assertEqual(self.run_observer('--check').returncode,0)
 def test_wrong_detached_pin_rejected(self):
  self.env['TU1NZ_EXPECTED_DETACHED_HEAD']='0'*40;self.assertNotEqual(self.run_observer('--check').returncode,0)
 def test_unpinned_detached_rejected(self):
  self.env.pop('TU1NZ_EXPECTED_DETACHED_HEAD');self.assertNotEqual(self.run_observer('--check').returncode,0)
 def test_control_bytes_refs_unchanged(self):
  before=self.fingerprint(self.control);self.assertEqual(self.run_observer().returncode,0);self.assertEqual(before,self.fingerprint(self.control))
 def test_docs_local_changes_preserved(self):
  (self.docs/'tracked').write_text('foreign work');(self.docs/'untracked').write_text('foreign new');before=self.fingerprint(self.docs)
  self.assertEqual(self.run_observer().returncode,0);self.assertEqual(before,self.fingerprint(self.docs))
  self.assertEqual(json.loads((self.root/'state/control_update_state.json').read_text())['docs_status'],'DOCS_LOCAL_CHANGES_PRESERVED')
 def test_second_run_no_duplicate_notification(self):
  self.assertEqual(self.run_observer().returncode,0);self.assertEqual(self.run_observer().returncode,0);self.assertEqual(len(self.calls.read_text().splitlines()),1)
 def test_lock_contention_no_processing(self):
  (self.root/'run').mkdir();fd=os.open(self.root/'run/lock',os.O_CREAT|os.O_RDWR,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(self.run_observer().returncode,0);self.assertFalse(self.calls.exists());self.assertFalse((self.root/'state/control_update_state.json').exists())
  finally:os.close(fd)
 def test_loop_start_health_stop(self):
  p=subprocess.Popen(['/bin/bash',str(SOURCE),'--loop'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
  try:
   deadline=time.monotonic()+10
   while not (self.root/'state/control_update_state.json').exists():
    self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.05)
   self.assertEqual(json.loads((self.root/'state/control_update_state.json').read_text())['status'],'CONTROL_CURRENT')
  finally:
   os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=3)
  self.assertEqual(p.returncode,-signal.SIGTERM);self.assertEqual(self.run_observer().returncode,0)
 def test_no_mutating_git_or_approval_api(self):
  s=SOURCE.read_text();self.assertNotIn(' reset --hard',s);self.assertNotIn(' fetch --all',s);self.assertNotIn('getUpdates',s);self.assertNotIn('approval',s.lower())
if __name__=='__main__':unittest.main()
