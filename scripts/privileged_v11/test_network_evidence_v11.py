import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from network_evidence_v11 import *

class EvidenceTests(unittest.TestCase):
 def test_docker_dnat_exact(self):
  r=nat_evidence(b'*nat\n-A DOCKER -p tcp --dport 8081 -j DNAT --to-destination 172.25.0.2:8080\nCOMMIT\n')
  self.assertTrue(r['docker_chain_mapping_verified'])
 def test_manual_rule_is_not_docker(self):
  self.assertFalse(nat_evidence(b'-A PREROUTING -p tcp --dport 8081 -j DNAT --to-destination 172.25.0.2:8080')['docker_chain_mapping_verified'])
 def test_extra_rule_refuses(self):
  line=b'-A DOCKER -p tcp --dport 8081 -j DNAT --to-destination 172.25.0.2:8080\n'
  self.assertFalse(nat_evidence(line+line)['docker_chain_mapping_verified'])
 def test_wrong_destination_refuses(self):
  self.assertFalse(nat_evidence(b'-A DOCKER -p tcp --dport 8081 -j DNAT --to-destination 172.25.0.3:8080')['docker_chain_mapping_verified'])
 def test_ip_token_boundary(self):
  self.assertEqual(refs('http://172.25.0.20/'),[])
  # Address followed by :port must match, unlike the longer address above.
  self.assertIn('shared_ip',refs('172.25.0.2'))
  self.assertIn('shared_ip',refs('http://172.25.0.2:8080/health'))
  self.assertIn('hostport',refs('http://localhost:8081/health'))
  self.assertNotIn('hostport',refs('http://localhost:80810/'))
 def database(self,p,nodes='[]'):
  c=sqlite3.connect(p);c.execute('CREATE TABLE workflow_entity(nodes TEXT,connections TEXT,active INTEGER)');c.execute('INSERT INTO workflow_entity VALUES (?,?,1)',(nodes,'{}'));c.commit();c.close()
 def test_no_secret_output(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'db';self.database(p,json.dumps([{'token':'DUMMY_SECRET','target':'172.25.0.2'}]))
   r=inspect_db_copy(p);self.assertNotIn('DUMMY_SECRET',json.dumps(r));self.assertEqual(r['matches'][0]['references'],['shared_ip'])
 def test_invalid_json_fails(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'db';self.database(p,'bad')
   with self.assertRaises(json.JSONDecodeError):inspect_db_copy(p)
 def test_missing_schema_fails(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'db';sqlite3.connect(p).close()
   with self.assertRaises(EvidenceError):inspect_db_copy(p)
 def test_symlink_denied(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'file';p.write_bytes(b'fixture');q=Path(d)/'link';q.symlink_to(p)
   with self.assertRaises(OSError):bounded_read(q)
 def test_oversize_denied(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'file';p.write_bytes(b'xx')
   with self.assertRaises(EvidenceError):bounded_read(p,limit=1)
 def test_no_root_run(self):
  if os.geteuid()==0:self.skipTest('test is intentionally nonprivileged')
  with self.assertRaises(EvidenceError):collect('/tmp/not-v11')

if __name__=='__main__':unittest.main()
