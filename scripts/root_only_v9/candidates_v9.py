"""Pure compilation from verified originals to the one authorized candidate set."""
import base64
import hashlib
from policy_v9 import Refused,DROPIN
from contracts_v9 import QUARANTINE_HASHES,TRIGGER_SERVICES
from files_v9 import bytes_of
from lifecycle_v9 import unit_candidate
from host_v9 import SUDO_PATHS,NEW_SUDO,BROKER,HELPER,MYCB_UNIT,DROPIN_PATH,MASK,CRON_GUARD,NOTIFY_GUARD,remove_member_bytes
from sudo_candidate_v9 import prepare as sudo_prepare


def record(data,mode=0o644,gid=0):
 return {'data':None if data is None else base64.b64encode(data).decode(),'sha256':None if data is None else hashlib.sha256(data).hexdigest(),'mode':mode,'gid':gid}


def compile_candidates(originals,broker_bytes,helper_bytes,sudo_bytes):
 result={BROKER:record(broker_bytes,0o755),HELPER:record(helper_bytes,0o755),
  MYCB_UNIT:record(unit_candidate(bytes_of(originals[MYCB_UNIT])),originals[MYCB_UNIT]['mode']),
  DROPIN_PATH:record(DROPIN.encode()),NEW_SUDO:record(sudo_bytes,0o440)}
 for path,raw in sudo_prepare({p:bytes_of(originals[p]) for p in SUDO_PATHS}).items():
  result[path]=record(raw,originals[path]['mode'],originals[path]['gid'])
 for path in ('/etc/group','/etc/gshadow'):
  rec=originals[path];result[path]=record(remove_member_bytes(bytes_of(rec),path.endswith('gshadow')),rec['mode'],rec['gid'])
 for path,expected in QUARANTINE_HASHES.items():
  if originals[path].get('sha256')!=expected:raise Refused('quarantine baseline changed')
  if path.startswith('/etc/cron.d/'):result[path]=record(CRON_GUARD,originals[path]['mode'])
  elif path in ('/usr/local/bin/backup_notify.sh','/usr/local/bin/trendwatch_post.sh'):result[path]=record(NOTIFY_GUARD,originals[path]['mode'])
 for unit in TRIGGER_SERVICES:
  path='/etc/systemd/system/'+unit
  if originals[path].get('absent'):raise Refused('missing quarantine unit')
  result[path]=record(MASK,originals[path]['mode'])
 return result
