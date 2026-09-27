import unittest
import tu1nz_pkcheck_review as m
class Tests(unittest.TestCase):
 def row(self):return {'argv':['/usr/bin/pkcheck','--action-id','org.freedesktop.packagekit.package-install','--process','1,2,1001'],'rc':2,'timeout':False,'overflow':False,'stdout_raw':{'bytes':0},'stderr_raw':{'bytes':60,'sha256':m.AUTH_REQUIRED_STDERR_SHA}}
 def test_challenge_is_not_authorized(self):self.assertEqual(m.classify(self.row()),'NOT_AUTHORIZED_AUTH_REQUIRED')
 def test_unexpected_error_not_relaxed(self):
  for field,value in [('rc',127),('rc',126),('rc',3),('timeout',True),('overflow',True),('stderr_raw',{'bytes':60,'sha256':'wrong'}),('stdout_raw',{'bytes':1})]:
   r=self.row();r[field]=value;self.assertEqual(m.classify(r),'ERROR')
 def test_allow_and_deny_distinct(self):
  r=self.row();r['rc']=0;self.assertEqual(m.classify(r),'AUTHORIZED');r['rc']=1;self.assertEqual(m.classify(r),'NOT_AUTHORIZED')
 def test_interactive_args_rejected(self):
  r=self.row();r['argv'].append('--allow-user-interaction');self.assertEqual(m.classify(r),'ERROR')
if __name__=='__main__':unittest.main()
