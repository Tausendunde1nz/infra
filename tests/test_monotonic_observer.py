import copy, json, unittest, subprocess, sys
from unittest.mock import patch
import tu1nz_policy_watchdog as w
from tu1nz_monotonic_observer import valid_observation, SECOND, monotonic_ns

def fixture():
    start=10*SECOND
    activation={'sha256':'candidate','observation_start_ns':start}
    obs={'transaction':'a','candidate_sha256':'candidate','observation_start_ns':start,
         'completed_monotonic_ns':105*SECOND,'complete':True,'samples':[]}
    for minimum,actual in [(0,10),(30,41),(60,71),(90,105)]:
        obs['samples'].append({'minimum_seconds':minimum,'started_monotonic_ns':actual*SECOND,
          'finished_monotonic_ns':actual*SECOND,'passed':True,'evidence_sha256':'0'*64})
    raw=json.dumps(obs).encode()
    manifest={'transaction':'a','candidate_sha256':'candidate','candidate_semantic_hex':b'{}'.hex(),
      'stage':'phase5','deadline_monotonic_ns':120*SECOND}
    report=json.dumps({'checks':{k:True for k in w.REQUIRED},'completed_monotonic_ns':111*SECOND,
      'observation_sha256':w.sha(raw)}).encode()
    marker={'transaction':'a','candidate_sha256':'candidate','report_sha256':w.sha(report)}
    return manifest,activation,raw,report,marker

class MonotonicTests(unittest.TestCase):
    def test_real_cross_process_monotonic_clock_domain(self):
        before=monotonic_ns()
        child=int(subprocess.check_output([sys.executable,'-c','import time;print(time.clock_gettime_ns(time.CLOCK_MONOTONIC))'],text=True))
        after=monotonic_ns()
        self.assertLessEqual(before,child);self.assertLessEqual(child,after)
    def setUp(self):
        self.manifest,self.activation,self.raw,self.report,self.marker=fixture()
        self.obs=json.loads(self.raw)
    def valid(self,obs=None,now=112*SECOND):
        return valid_observation(self.obs if obs is None else obs,self.activation,'a',now)
    def test_95_seconds_pass(self):self.assertTrue(self.valid())
    def test_89_point_9_seconds_rejected(self):
        self.obs['completed_monotonic_ns']=self.activation['observation_start_ns']+89_900_000_000
        self.obs['samples'][-1]['started_monotonic_ns']=self.obs['completed_monotonic_ns']
        self.obs['samples'][-1]['finished_monotonic_ns']=self.obs['completed_monotonic_ns']
        self.assertFalse(self.valid())
    def test_early_process_end_no_complete_rejected(self):
        self.obs['complete']=False;self.obs['samples'].pop();self.assertFalse(self.valid())
    def test_missing_last_sample_rejected(self):
        self.obs['samples'].pop();self.assertFalse(self.valid())
    def test_early_checkpoint_rejected(self):
        self.obs['samples'][1]['started_monotonic_ns']=self.activation['observation_start_ns']+29_900_000_000
        self.assertFalse(self.valid())
    def test_no_immediate_sample_rejected(self):
        self.obs['samples'][0]['started_monotonic_ns']=31*SECOND
        self.obs['samples'][0]['finished_monotonic_ns']=31*SECOND
        self.assertFalse(self.valid())
    def test_failed_sample_rejected(self):
        self.obs['samples'][2]['passed']=False;self.assertFalse(self.valid())
    def test_different_transaction_rejected(self):
        self.obs['transaction']='other';self.assertFalse(self.valid())
    def test_different_readback_start_rejected(self):
        self.obs['observation_start_ns']-=SECOND;self.assertFalse(self.valid())
    def test_future_evidence_rejected(self):self.assertFalse(self.valid(now=104*SECOND))
    def test_wall_clock_jumps_irrelevant(self):
        for wall in [-1000000000,999999999999]:
            with patch.object(w.time,'time',return_value=wall):
                self.assertTrue(w.valid_completion(self.marker,self.manifest,self.report,{'json':b'{}'},112*SECOND,self.activation,self.raw))
    def test_observation_hash_mismatch_rejected(self):
        self.assertFalse(w.valid_completion(self.marker,self.manifest,self.report,{'json':b'{}'},112*SECOND,self.activation,self.raw+b' '))
    def test_early_process_end_watchdog_marker_rejected(self):
        self.obs['complete']=False
        raw=json.dumps(self.obs).encode();r=json.loads(self.report);r['observation_sha256']=w.sha(raw)
        report=json.dumps(r).encode();marker=dict(self.marker,report_sha256=w.sha(report))
        self.assertFalse(w.valid_completion(marker,self.manifest,report,{'json':b'{}'},112*SECOND,self.activation,raw))
    def test_89_point_9_watchdog_cannot_disarm(self):
        self.obs['completed_monotonic_ns']=self.activation['observation_start_ns']+89_900_000_000
        raw=json.dumps(self.obs).encode();r=json.loads(self.report);r['observation_sha256']=w.sha(raw)
        report=json.dumps(r).encode();marker=dict(self.marker,report_sha256=w.sha(report))
        self.assertFalse(w.valid_completion(marker,self.manifest,report,{'json':b'{}'},112*SECOND,self.activation,raw))

if __name__=='__main__':unittest.main()
