"""Pure candidate generation; no installation, service calls, or secret output."""
import hashlib
class Refused(ValueError):pass
POST_SHA='467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264'
UNIT_SHA={
 'trendwatch2-morning.service':'c2eb07d31d4f11168c9c4a89faf150a329c72305c4e26fea3be9d078264ab191',
 'trendwatch2-midday.service':'08cf1b77d0f1d2619f17f8568f011dd6a6884bf8d63ee94e47447ca8cb4d5b09',
 'trendwatch2-afternoon.service':'5f12ab31cf29e5fa6cd8be6b71feee4c00961de0efcc1da70ebb02218d528796',
 'trendwatch2-evening.service':'c7aa32d4a8860581294b851b47f8c651223a7e03589879d13310b8209d6648ae',
}
NEW_POST='/usr/local/libexec/tu1nz-privileged-v11/trendwatch_post.sh'

def trendwatch_post(original):
 if hashlib.sha256(original).hexdigest()!=POST_SHA:raise Refused('TRENDWATCH_SOURCE_DRIFT')
 return _post_transform(original)

def _post_transform(original):
 text=original.decode()
 for a,b in [('sudo mkdir -p /opt/trendwatch','mkdir -p /opt/trendwatch'),('sudo tee /opt/trendwatch/today_title.txt','tee /opt/trendwatch/today_title.txt')]:
  if text.count(a)!=1:raise Refused('EXPECTED_CALL_COUNT')
  text=text.replace(a,b)
 # Retain application behavior and credentials in protected runtime bytes only.
 if 'sudo ' in text:raise Refused('UNREVIEWED_SUDO')
 return text.encode()

def trendwatch_unit(name,original):
 if name not in UNIT_SHA or hashlib.sha256(original).hexdigest()!=UNIT_SHA[name]:raise Refused('UNIT_DRIFT')
 text=original.decode()
 if text.count('/usr/local/bin/trendwatch_post.sh')!=1:raise Refused('EXECUTABLE_COUNT')
 if any(line.startswith(('User=','Group=','SupplementaryGroups=','AmbientCapabilities=')) for line in text.splitlines()):raise Refused('UNIT_IDENTITY')
 return '[Service]\nUser=chatops\nGroup=chatops\nSupplementaryGroups=\nNoNewPrivileges=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=true\nExecStart=\n'+next(l.replace('/usr/local/bin/trendwatch_post.sh',NEW_POST) for l in text.splitlines() if l.startswith('ExecStart='))+'\n'

def document_worker_unit():
 return '''[Unit]
Description=TU1NZ V11 unprivileged document rendering
[Service]
Type=oneshot
User=chatops
Group=chatops
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=true
UMask=0077
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/tu1nz-privileged-v11/doc_worker.py
TimeoutStartSec=240
'''
