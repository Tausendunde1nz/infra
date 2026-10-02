"""Exact authorized supersession. A descendant alone never grants admission."""
import re
HEAD='e60aa2f515c89f94bce1dbd6496d358cdfb85300'
TREE='4640102c40af0111be62b845842f0d7b99ca69f2'
PREVIOUS='21e822f8cadecf5eb186693d1ceac2d5d0bf6969'
FORBIDDEN_RESTORE={PREVIOUS,'b78bb2a753aa815d47a99969668d64960573050b'}
PATHS=frozenset(('managed/bin/tu1nz-mychatbuddy-rc5-controlled-start','managed/tests/test_mychatbuddy_rc5_controlled_start.py','plans/business/MYCHATBUDDY_RC5_CONTROLLED_START_V2.md','plans/business/MYCHATBUDDY_RC5_POST_HEALTH_ROLLBACK_2026-10-02.diagnose'))
class Refused(ValueError):pass

def admit(observation,transition):
 if observation['active_writer'] is not False:raise Refused('ACTIVE_OR_UNKNOWN_WRITER')
 if observation['tracked_match'] is not True:raise Refused('LOCAL_TRACKED_MUTATION')
 a,b=observation['index_before'],observation['index_after']
 for index in (a,b):
  if index['uid']!=1001 or index['gid']!=1001 or index['mode']!=0o600 or index['nlink']!=1 or index['regular'] is not True:raise Refused('INDEX_OWNERSHIP_OR_TYPE')
  if not re.fullmatch('[0-9a-f]{64}',index['sha256']):raise Refused('INDEX_HASH')
 if a!=b:raise Refused('INDEX_MUTATION_DURING_OBSERVATION')
 if observation['head'] in FORBIDDEN_RESTORE:raise Refused('SUPERSEDED_BASE')
 if observation['head']!=HEAD:raise Refused('UNKNOWN_COMMIT')
 if observation['tree']!=TREE:raise Refused('TREE_MISMATCH')
 expected={'from':PREVIOUS,'to':HEAD,'tree':TREE,'merge_base':PREVIOUS,'ahead':8,'behind':0,'changed_paths':sorted(PATHS),'authorized':True}
 if transition!=expected:raise Refused('UNAUTHORIZED_SUPERSESSION')
 return {'status':'AUTHORIZED_FORWARD_SUPERSESSION','head':HEAD,'tree':TREE,'root_index_writes':False,'live_start_authorized':False}
