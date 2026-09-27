#!/usr/bin/env python3
"""Bounded public TCP admission checks, compatible with Python3.9+.
A timeout/refusal proves only that this fresh attempt did not connect.
No-route is inconclusive; any successful connect is a failing security gate.
"""
import argparse,errno,json,socket,unittest
ADDRESSES=('91.98.112.14','2a01:4f8:1c1a:f152::1')
PORTS=(22,2222,3000,8080,8090,9100)
def classify(error):
 if isinstance(error,(socket.timeout,TimeoutError)) or error.errno==errno.ETIMEDOUT:return 'BLOCKED_TIMEOUT'
 if error.errno==errno.ECONNREFUSED:return 'REFUSED'
 if error.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH):return 'INCONCLUSIVE_NO_ROUTE'
 raise error

def probe(address,port,connect=None):
 if address not in ADDRESSES or port not in PORTS:raise ValueError('Out-of-scope endpoint')
 connect=socket.create_connection if connect is None else connect
 try:
  with connect((address,port),timeout=2):pass
 except OSError as error:return classify(error)
 return 'FAIL_CONNECTED'

def passed(results):
 expected={(a,p) for a in ADDRESSES for p in PORTS}
 if len(results)!=len(expected) or {(x['address'],x['port']) for x in results}!=expected:return False
 return all(x['result'] in ('BLOCKED_TIMEOUT','REFUSED') for x in results)

class Checks(unittest.TestCase):
 def test_timeouts(self):
  for error in (socket.timeout('timed out'),TimeoutError('timed out'),OSError(errno.ETIMEDOUT,'timed out')):self.assertEqual(classify(error),'BLOCKED_TIMEOUT')
 def test_refused(self):self.assertEqual(classify(OSError(errno.ECONNREFUSED,'refused')),'REFUSED')
 def test_no_route_not_success(self):
  rows=[{'address':a,'port':p,'result':'REFUSED'} for a in ADDRESSES for p in PORTS]
  self.assertTrue(passed(rows));rows[0]['result']=classify(OSError(errno.ENETUNREACH,'no route'));self.assertFalse(passed(rows))
 def test_successful_connect_fails(self):
  class Connection:
   def __enter__(self):return self
   def __exit__(self,*args):pass
  self.assertEqual(probe(ADDRESSES[0],22,lambda *a,**kw:Connection()),'FAIL_CONNECTED')
  rows=[{'address':a,'port':p,'result':'REFUSED'} for a in ADDRESSES for p in PORTS];rows[0]['result']='FAIL_CONNECTED';self.assertFalse(passed(rows))
 def test_unexpected_error_propagates(self):
  with self.assertRaises(OSError):classify(OSError(errno.EACCES,'denied'))
 def test_scope_and_completeness(self):
  with self.assertRaises(ValueError):probe('127.0.0.1',22)
  with self.assertRaises(ValueError):probe(ADDRESSES[0],443)
  self.assertFalse(passed([]))
  rows=[{'address':ADDRESSES[0],'port':22,'result':'REFUSED'}]*12;self.assertFalse(passed(rows))
if __name__=='__main__':
 parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group(required=True)
 group.add_argument('--self-test',action='store_true');group.add_argument('--probe',action='store_true');args=parser.parse_args()
 if args.self_test:
  result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks));raise SystemExit(0 if result.wasSuccessful() else 1)
 rows=[]
 for address in ADDRESSES:
  for port in PORTS:
   row={'address':address,'port':port,'result':probe(address,port)};rows.append(row);print(json.dumps(row),flush=True)
 raise SystemExit(0 if passed(rows) else 1)
