import unittest,importlib.util,pathlib,socket,errno,sys
from unittest.mock import patch
BASE=pathlib.Path(__file__).parent
if not (BASE/'phase5-extended-check.py').exists():BASE=BASE.parent/'scripts'
sys.path.insert(0,str(BASE))
path=BASE/('phase5-extended-check.py' if (BASE/'phase5-extended-check.py').exists() else 'tu1nz_phase5_extended_mac_check.py')
s=importlib.util.spec_from_file_location('checker',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
import tu1nz_policy_watchdog as w
class T(unittest.TestCase):
 def test_socket_timeout(self):
  with patch.object(m.socket,'create_connection',side_effect=socket.timeout()):self.assertTrue(m.closed_tcp('::1',2222))
 def test_builtin_timeout(self):
  with patch.object(m.socket,'create_connection',side_effect=TimeoutError()):self.assertTrue(m.closed_tcp('::1',2222))
 def test_refused(self):
  with patch.object(m.socket,'create_connection',side_effect=ConnectionRefusedError()):self.assertTrue(m.closed_tcp('::1',2222))
 def test_no_route(self):
  with patch.object(m.socket,'create_connection',side_effect=OSError(errno.ENETUNREACH,'test')):
   with self.assertRaises(OSError):m.closed_tcp('::1',2222)
 def test_permission(self):
  with patch.object(m.socket,'create_connection',side_effect=OSError(errno.EACCES,'test')):
   with self.assertRaises(OSError):m.closed_tcp('::1',2222)
 def test_open(self):
  class Open:
   def __enter__(self):return self
   def __exit__(self,*a):pass
  with patch.object(m.socket,'create_connection',return_value=Open()):self.assertFalse(m.closed_tcp('::1',2222))
 def test_api_timeout_retry_budget(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'},sleep=lambda x:None)
  with patch.object(a.opener,'open',side_effect=socket.timeout()) as op:
   with self.assertRaises(w.SafeError):a.wire(w.ACL)
   self.assertEqual(op.call_count,4)
if __name__=='__main__':unittest.main()
