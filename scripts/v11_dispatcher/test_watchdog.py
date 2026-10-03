import sys,copy,unittest,tempfile
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent/'v11_guard_recovery'))
from watchdog import *
B={'transaction':'v11-'+'a'*32,'origin_boot':'01234567-89ab-cdef-0123-456789abcdef','contract_sha256':'b'*64}
class Host:
 def __init__(self):
  self.current={'binding':{'transaction':B['transaction'],'boot':B['origin_boot'],'contract_sha256':B['contract_sha256'],'deadline_ns':100},'sealed':False,'phase':'PREPARED'};self.boot=B['origin_boot'];self.now=200;self.alive=False;self.events=[];self.saved=None;self.state='inactive';self.tip='0'*64;self.verified=False
 def observe(self):return B,self.current,self.boot,self.now,self.alive
 def close_fence(self):self.events.append('CLOSED')
 def secured(self):self.events.append('STOP');return 'SECURED_STOP'
 def forward_terminal(self,binding):return self.verified
 def preseal_terminal(self,binding):return self.verified
 def progress(self):return self.tip
 def read_watchdog(self):return copy.deepcopy(self.saved)
 def write_watchdog(self,v):self.saved=copy.deepcopy(v)
 def worker(self):return self.state
 def stop_worker(self):self.events.append('STOP_WORKER');self.state='inactive'
 def dispatch(self):self.events.append('DISPATCH');self.state='activating'
class WatchdogTests(unittest.TestCase):
 def test_live_lease_never_dispatches(self):
  h=Host();h.now=99;h.alive=True;self.assertEqual(tick(h),'WAIT');self.assertEqual(h.events,[])
 def test_dead_coordinator_dispatches_with_closed_fence(self):
  h=Host();self.assertEqual(tick(h),'DISPATCHED');self.assertEqual(h.events,['CLOSED','DISPATCH'])
 def test_running_worker_not_restarted_without_stall(self):
  h=Host();h.state='active';self.assertEqual(tick(h),'WORKER_RUNNING');self.assertNotIn('STOP_WORKER',h.events)
 def test_stall_restarts_bounded_then_stops(self):
  h=Host();tick(h)
  for i in range(MAX_RESTARTS):
   h.now+=STALL_NS;self.assertEqual(tick(h),'DISPATCHED');self.assertEqual(h.saved['restarts'],i+1)
  h.now+=STALL_NS;self.assertEqual(tick(h),'SECURED_STOP')
 def test_progress_extends_stall_window(self):
  h=Host();tick(h);h.now+=STALL_NS;h.tip='1'*64;self.assertEqual(tick(h),'WORKER_RUNNING');self.assertEqual(h.saved['restarts'],0)
 def test_reboot_preserves_retry_count(self):
  h=Host();tick(h);h.now+=STALL_NS;tick(h);h.boot='fedcba98-7654-3210-fedc-ba9876543210';h.now=1;h.state='inactive';self.assertEqual(tick(h),'DISPATCHED');self.assertEqual(h.saved['restarts'],1)
 def test_clock_rewind_stops(self):
  h=Host();tick(h);h.now=199;self.assertEqual(tick(h),'SECURED_STOP')
 def test_foreign_transaction_state_stops(self):
  h=Host();tick(h);h.saved['binding']['transaction']='v11-'+'f'*32;self.assertEqual(tick(h),'SECURED_STOP')
 def test_unknown_worker_stops(self):
  h=Host();h.state='mystery';self.assertEqual(tick(h),'SECURED_STOP')
 def test_postseal_never_preseal_rollback(self):
  h=Host();h.current['sealed']=True;self.assertEqual(tick(h),'SECURED_STOP');self.assertNotIn('DISPATCH',h.events)
 def test_verified_terminal_not_periodically_closed(self):
  h=Host();h.current['phase']='ROLLED_BACK_PRESEAL';h.verified=True;self.assertEqual(tick(h),'VERIFIED_PRESEAL_TERMINAL');self.assertEqual(h.events,[])
 def test_forward_terminal_requires_proof(self):
  h=Host();h.current.update(phase='COMPLETED',sealed=True);self.assertEqual(tick(h),'SECURED_STOP');h.verified=True;self.assertEqual(tick(h),'VERIFIED_FORWARD_TERMINAL')
 def test_observer_error_stops(self):
  h=Host();h.observe=lambda:(_ for _ in ()).throw(RuntimeError());self.assertEqual(tick(h),'SECURED_STOP')
 def test_watchdog_lock_independent_of_worker(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-dispatcher-test-',dir='/tmp') as d:
   s=core.Durable(d,fixture=True);s.initialize(B)
   try:
    with s.locked():
     with s.locked('watchdog.lock'):pass
    with s.locked('watchdog.lock'):
     with self.assertRaises(BlockingIOError):
      with s.locked('watchdog.lock'):pass
   finally:s.close()
if __name__=='__main__':unittest.main()
