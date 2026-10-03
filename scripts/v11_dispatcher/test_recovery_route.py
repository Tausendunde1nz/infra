import copy,unittest
from recovery_route import *
B={'transaction':'v11-'+'a'*32,'origin_boot':'01234567-89ab-cdef-0123-456789abcdef','contract_sha256':'b'*64}
class Routing(unittest.TestCase):
 def state(self,sealed=False,phase='PREPARED'):
  return {'binding':{'transaction':B['transaction'],'boot':B['origin_boot'],'contract_sha256':B['contract_sha256'],'deadline_ns':100},'sealed':sealed,'phase':phase}
 def test_live_coordinator_waits(self):
  for sealed in (False,True):self.assertEqual(route(B,self.state(sealed),B['origin_boot'],99,True),'WAIT')
 def test_expiry_never_rolls_back_sealed(self):
  self.assertEqual(route(B,self.state(),B['origin_boot'],100,True),'RECOVER_PRESEAL');self.assertEqual(route(B,self.state(True),B['origin_boot'],100,True),'SECURED_STOP')
 def test_dead_coordinator(self):self.assertEqual(route(B,self.state(),B['origin_boot'],1,False),'RECOVER_PRESEAL')
 def test_reboot(self):self.assertEqual(route(B,self.state(),'fedcba98-7654-3210-fedc-ba9876543210',1,True),'RECOVER_PRESEAL')
 def test_foreign_binding(self):
  s=self.state();s['binding']['transaction']='v11-'+'c'*32
  with self.assertRaises(Refused):route(B,s,B['origin_boot'],1,True)
 def test_terminals_only_verified(self):
  self.assertEqual(route(B,self.state(False,'ROLLED_BACK_PRESEAL'),B['origin_boot'],1000,False),'VERIFY_PRESEAL_TERMINAL');self.assertEqual(route(B,self.state(True,'COMPLETED'),B['origin_boot'],1000,False),'VERIFY_FORWARD_TERMINAL')
 def test_contradiction(self):
  for s in [self.state(True,'ROLLED_BACK_PRESEAL'),self.state(False,'COMPLETED')]:
   with self.assertRaises(Refused):route(B,s,B['origin_boot'],1,True)
if __name__=='__main__':unittest.main()
