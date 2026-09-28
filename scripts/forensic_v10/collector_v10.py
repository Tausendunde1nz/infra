"""One-shot read-only root forensics. Only OUTPUT is intentionally written.

No action on import; no service/container actions, no network health requests.
Normal OS audit/accounting of read commands is not suppressed or modified.
"""
import base64
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

VERSION='10.0'
CONTROL_FLOW={'classification': 'MUTATION_REACHABLE_BEFORE_REFUSAL', 'capsule_sha256': '865b33e81db52f497fe834293619ef933f1bfa38ab80b715e91b51c98c342690', 'implicit_import_cache_write_possible': True, 'historical_python_binary_digest': 'NOT_BOUND'}
PRIOR_UNIT={'sha256': '53a2fad8675a6cfa79196d2fea64e56745403cdc4802ae93cb32682c13d71d26', 'directives': [{'section': '[Unit]', 'directive': 'Description', 'value_sha256': 'cf73f2cf9f1c55dce6caeb1ad0540496955a5c6188d73b74a48d2b406b649681'}, {'section': '[Unit]', 'directive': 'Documentation', 'value_sha256': '7363ccab12f564ac72acb5b0d9794fb15dd90829f781c0876691673223302902'}, {'section': '[Unit]', 'directive': 'After', 'value_sha256': '2d9f791dcea219f5a6fd106b2ebdb164821a162f4509c872a8058c0dd924a51a'}, {'section': '[Unit]', 'directive': 'Wants', 'value_sha256': '2d9f791dcea219f5a6fd106b2ebdb164821a162f4509c872a8058c0dd924a51a'}, {'section': '[Unit]', 'directive': 'Requires', 'value_sha256': '3538035ad9649afabaad12e73dd0e6ce7558b0d9c98d8d1b48483254182a68f3'}, {'section': '[Unit]', 'directive': 'ConditionPathExists', 'value_sha256': '82eae4a19d03a6b0d1ffc5fbc964587206563f46a2bb6ce0bcdcdcee4d451273'}, {'section': '[Unit]', 'directive': 'ConditionPathIsDirectory', 'value_sha256': '2754210a33e9dc6e2eae62922dd84652e69888129ba3560382197b3ec9bf5cd1'}, {'section': '[Unit]', 'directive': 'ConditionPathIsDirectory', 'value_sha256': '045a8a5d8843fbce090c32c641a21a35ae3c08995f0b6dfc69e29c4a0eb5d856'}, {'section': '[Unit]', 'directive': 'ConditionPathExists', 'value_sha256': '71329c4cc6e32171553fa81d044eb31d1a3aac52ba9376c4a99f4505c494cf5b'}, {'section': '[Service]', 'directive': 'Type', 'value_sha256': 'a7a39b72f29718e653e73503210fbb597057b7a1c77d1fe321a1afcff041d4e1', 'safe_value': 'simple'}, {'section': '[Service]', 'directive': 'User', 'value_sha256': 'b06958cd80ca2adc17fe1d417c2569c2b284be82385cc710871922106765b83b', 'safe_value': 'tu1nz-mychatbuddy'}, {'section': '[Service]', 'directive': 'Group', 'value_sha256': 'b06958cd80ca2adc17fe1d417c2569c2b284be82385cc710871922106765b83b', 'safe_value': 'tu1nz-mychatbuddy'}, {'section': '[Service]', 'directive': 'SupplementaryGroups', 'value_sha256': 'd548c5b83fa61d8e3bd86ad42a7ffea9b7c86e3f9d8095c1577d3e1270bb9420', 'safe_value': 'docker'}, {'section': '[Service]', 'directive': 'UMask', 'value_sha256': 'ddfcd6f752faf5e5ba65da9c6e1dbc5be379156eccc152a098ebe52f74d1fd52', 'safe_value': '0077'}, {'section': '[Service]', 'directive': 'EnvironmentFile', 'value_sha256': '82eae4a19d03a6b0d1ffc5fbc964587206563f46a2bb6ce0bcdcdcee4d451273'}, {'section': '[Service]', 'directive': 'LoadCredential', 'value_sha256': 'f1d4de88d64d7f6007d10def04a24cca76bd2d80a02e2eae78f42d3c64c6dc73'}, {'section': '[Service]', 'directive': 'LoadCredential', 'value_sha256': '91d73a7541335b69a67fd521502ee4b53880bba02e1e49c24c77f71e470f1b98'}, {'section': '[Service]', 'directive': 'LoadCredential', 'value_sha256': '1fb36e45fe037705358f228838fa20757d9eb3add11957e79f79ab6779ca1b4a'}, {'section': '[Service]', 'directive': 'LoadCredential', 'value_sha256': '161418153f1ded988200ac54cf40171bbfb863c8da643691d95eced5e464794c'}, {'section': '[Service]', 'directive': 'LoadCredential', 'value_sha256': '1ef5e37804dfd20b2df1920faac0fb1c4165d2ad226563cf44b2668b6d9b4408'}, {'section': '[Service]', 'directive': 'RuntimeDirectory', 'value_sha256': '5cc2866ec6858df1941991ea1be1fb88753d90127e688a713b6ef9151e81196d'}, {'section': '[Service]', 'directive': 'RuntimeDirectoryMode', 'value_sha256': '3afc20e93f4a8c5281ad23fb3da6d548e6324de195e3de4d0865555f3e623762', 'safe_value': '0700'}, {'section': '[Service]', 'directive': 'RuntimeDirectoryPreserve', 'value_sha256': '9390298f3fb0c5b160498935d79cb139aef28e1c47358b4bbba61862b9c26e59'}, {'section': '[Service]', 'directive': 'StateDirectory', 'value_sha256': 'c9334b5300bb49a91b75875d7c38058118ab253b5daba42c85deca8e7e3ff021'}, {'section': '[Service]', 'directive': 'StateDirectoryMode', 'value_sha256': '3afc20e93f4a8c5281ad23fb3da6d548e6324de195e3de4d0865555f3e623762', 'safe_value': '0700'}, {'section': '[Service]', 'directive': 'LogsDirectory', 'value_sha256': 'c9334b5300bb49a91b75875d7c38058118ab253b5daba42c85deca8e7e3ff021'}, {'section': '[Service]', 'directive': 'LogsDirectoryMode', 'value_sha256': 'a27c7465ecc37619aa2b46e1186c68e4c659dfc6406b6e72397e0844e4b32a91', 'safe_value': '0750'}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': '7c6592523abfd58487345cffb5f5bd1d0fc2eb376f8a0a5bf03a30b291f5dd14', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': '9d42ae2aac9f420b43777e124b266ca13b00151a400e4aa0ab34d48ddcdf851c', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': 'f8e522c950b3618091bf6341176b2702730d00f3961eb1f8ec884cbc57199d05', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': '0685091806c7f0d045b9c91c035c0fed4b758245ab5a1208cc3ceb9fc24014d2', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': 'd70087a4fce6aa6b3086d9b8b6ee665860d6b9f380e6a4ac74664c105618d8b5', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': '523d64e0fe4f9c17e4254f0990c7e1a5525eefa2d9055be106baffa91868d0eb', 'executable': '+/usr/bin/install', 'argument_count': 8}, {'section': '[Service]', 'directive': 'ExecStartPre', 'value_sha256': 'cb3a71d929c22d263215265bbb91e83aba0c6a484429a7f01130c8d023851efb', 'executable': '/usr/bin/docker', 'argument_count': 3}, {'section': '[Service]', 'directive': 'ExecStart', 'value_sha256': 'ca295b99c23167a47d04d5325ef01268eef40e4a4e2181e97059026afa944cfc', 'executable': '/usr/bin/docker', 'argument_count': 113}, {'section': '[Service]', 'directive': 'ExecStop', 'value_sha256': '651d4dd6878e3d3ed19840fae636fb7ac77ed33f1f93c35c6409102d9caafa23', 'executable': '-/usr/bin/docker', 'argument_count': 4}, {'section': '[Service]', 'directive': 'Restart', 'value_sha256': '9390298f3fb0c5b160498935d79cb139aef28e1c47358b4bbba61862b9c26e59', 'safe_value': 'no'}, {'section': '[Service]', 'directive': 'SuccessExitStatus', 'value_sha256': 'd6f0c71ef0c88e45e4b3a2118fcb83b0def392d759c901e9d755d0e879028727', 'safe_value': '143'}, {'section': '[Service]', 'directive': 'TimeoutStartSec', 'value_sha256': 'a92bebd7bd67cb7c234b13dc5716d5b460d8de38432b91c6d34d9f9f7fa6f942', 'safe_value': '120s'}, {'section': '[Service]', 'directive': 'TimeoutStopSec', 'value_sha256': '878d17c0f5523afbbc8e8e8aa97963ee984be04619c3322bbfcfe1cc736b5c84', 'safe_value': '45s'}, {'section': '[Service]', 'directive': 'KillMode', 'value_sha256': '19ed40bf62c399b8492efda5b9a9184b68cf4d9d4a165b38557b9d14201d0c03', 'safe_value': 'process'}, {'section': '[Service]', 'directive': 'NoNewPrivileges', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'PrivateTmp', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'PrivateDevices', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectSystem', 'value_sha256': '3a3127f5ea0269b5c6cfe92e7eb12dccc190b1e1cedd7faeae3960079542c055', 'safe_value': 'strict'}, {'section': '[Service]', 'directive': 'ProtectHome', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectKernelTunables', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectKernelModules', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectKernelLogs', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectControlGroups', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectClock', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectHostname', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'ProtectProc', 'value_sha256': 'b75af7ef6c4de2b99053f7f6c005d549e95be118be0eb500f1cf86f36ec8f324', 'safe_value': 'invisible'}, {'section': '[Service]', 'directive': 'ProcSubset', 'value_sha256': 'ce71df4dc560de1e3e3d08a85db646710b493e3106c7af94ae10372d61f9eda8', 'safe_value': 'pid'}, {'section': '[Service]', 'directive': 'RestrictSUIDSGID', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'LockPersonality', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'MemoryDenyWriteExecute', 'value_sha256': '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d', 'safe_value': 'yes'}, {'section': '[Service]', 'directive': 'CapabilityBoundingSet', 'value_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'safe_value': ''}, {'section': '[Service]', 'directive': 'AmbientCapabilities', 'value_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'safe_value': ''}, {'section': '[Service]', 'directive': 'RestrictAddressFamilies', 'value_sha256': '580e76b31a0e9f9c4aebd9062856dca9c3ee5b82fec68311636dd7b5e18e5b48', 'safe_value': 'AF_UNIX'}, {'section': '[Service]', 'directive': 'ReadOnlyPaths', 'value_sha256': '82eae4a19d03a6b0d1ffc5fbc964587206563f46a2bb6ce0bcdcdcee4d451273'}, {'section': '[Service]', 'directive': 'ReadOnlyPaths', 'value_sha256': 'f2431a35ccf29d227154f4a115c4c30691baf8164f58a5f974f2bab6c6076eb5'}, {'section': '[Service]', 'directive': 'ReadWritePaths', 'value_sha256': '55b26733c08f4610e58e6d9a78b0b0a0c9d54bed2b122163636c143129b59cd0'}, {'section': '[Install]', 'directive': 'WantedBy', 'value_sha256': '9de81a63547dec5f7f8a96c0be07089a53af46cb430596fd610ea8df3387dba3'}]}
TXID='forensic-v10-20260928-2d6c7fc1c28946afa6c8213d0c4727bb' # replaced by binding at preparation
OLD_SHA='865b33e81db52f497fe834293619ef933f1bfa38ab80b715e91b51c98c342690'
OLD_STAGE='/home/chatops/.tu1nz-root-only-v9-'+OLD_SHA
OLD_ROOT='/var/lib/tu1nz-root-only-v9'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','HOME':'/var/empty','PYTHONDONTWRITEBYTECODE':'1'}
UNITS=('docker.service','docker.socket','ssh.service','tailscaled.service','fail2ban.service','tu1nz_agentmode.service','tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service','tu1nz-adult-public-s8-telegram.service','tu1nz-adult-public-s10-wms.service','mychatbuddy-private-alpha.service','tu1nz-bot.service','tu1nz-root-only-v9.service','tu1nz-root-only-v9-watchdog.service','tu1nz-root-only-v9-watchdog.timer')+tuple('trendwatch2-'+s+'.'+kind for s in ('morning','midday','afternoon','evening') for kind in ('service','timer'))
PROPS=('Id','LoadState','ActiveState','SubState','UnitFileState','FragmentPath','SourcePath','DropInPaths','MainPID','NRestarts','Result','ExecMainCode','ExecMainStatus','ExecMainStartTimestamp','ExecMainExitTimestamp','NeedDaemonReload','User','Group','SupplementaryGroups','SocketUser','SocketGroup','SocketMode','Listen','NextElapseUSecRealtime')
PATHS=('/etc/sudoers','/etc/group','/etc/gshadow','/run/docker.sock','/var/run/docker.sock','/etc/docker/daemon.json','/usr/lib/systemd/system/docker.socket','/usr/lib/systemd/system/docker.service','/etc/cron.d/system_doc_build','/etc/cron.d/system_doc_check','/usr/local/bin/backup_notify.sh','/usr/local/bin/trendwatch_post.sh','/usr/local/sbin/tu1nz-codex-ops','/usr/local/sbin/tu1nz-mychatbuddy-lifecycle','/run/tu1nz-root-only-v9.status.json','/etc/ssh/sshd_config','/etc/ufw/user.rules','/etc/ufw/user6.rules','/etc/ufw/ufw.conf','/etc/nftables.conf','/opt/trendwatch/today_title.txt','/opt/trendwatch/today_live_title.txt')
ARTIFACT_ROOTS=(OLD_STAGE,OLD_ROOT,'/usr/local/libexec/tu1nz-root-only-v9','/var/lib/tu1nz-codex-ops')
SAFE_UNIT_VALUES={'User','Group','SupplementaryGroups','Type','Restart','RestartForceExitStatus','SuccessExitStatus','RestartSec','TimeoutStartSec','TimeoutStopSec','KillMode','UMask','RuntimeDirectoryMode','StateDirectoryMode','LogsDirectoryMode','NoNewPrivileges','PrivateTmp','PrivateDevices','ProtectSystem','ProtectHome','ProtectKernelTunables','ProtectKernelModules','ProtectKernelLogs','ProtectControlGroups','ProtectClock','ProtectHostname','ProtectProc','ProcSubset','RestrictSUIDSGID','LockPersonality','MemoryDenyWriteExecute','CapabilityBoundingSet','AmbientCapabilities','RestrictAddressFamilies','StartLimitIntervalSec','StartLimitBurst','StartLimitAction'}
BOUND_BASELINES={'/etc/systemd/system/mychatbuddy-private-alpha.service': '53a2fad8675a6cfa79196d2fea64e56745403cdc4802ae93cb32682c13d71d26', '/etc/systemd/system/trendwatch2-afternoon.service': '5f12ab31cf29e5fa6cd8be6b71feee4c00961de0efcc1da70ebb02218d528796', '/etc/systemd/system/trendwatch2-afternoon.timer': 'ac440d7e461dedaa5b18097071a6c591b1a71233768a0a18ee206e782a39b892', '/etc/systemd/system/trendwatch2-evening.service': 'c7aa32d4a8860581294b851b47f8c651223a7e03589879d13310b8209d6648ae', '/etc/systemd/system/trendwatch2-evening.timer': '03108e3abf7388fe9fe971094222ef50cc4328cc2372a7206504a52937a1e1c9', '/etc/systemd/system/trendwatch2-midday.service': '08cf1b77d0f1d2619f17f8568f011dd6a6884bf8d63ee94e47447ca8cb4d5b09', '/etc/systemd/system/trendwatch2-midday.timer': '22d0e48498019b7243db808219c67232de4075597196bb0d5b41a15900143cfc', '/etc/systemd/system/trendwatch2-morning.service': 'c2eb07d31d4f11168c9c4a89faf150a329c72305c4e26fea3be9d078264ab191', '/etc/systemd/system/trendwatch2-morning.timer': '41ae60f43eacba069adefce022aace65b9f671768930dccc357f06e69f83638c', '/etc/systemd/system/tu1nz-adult-public-s8-telegram.service': 'fcad30a40a51ac9d45472cbe3e5eb607ccf117f820fe7f9a5d581f455aa63665', '/etc/systemd/system/tu1nz_agentmode.service': 'cc0ebe655f5fc843e8d8ded5ba321214aed58a8b1062b198606d1667dff356e1', '/usr/lib/systemd/system/docker.service': 'a12d90fd03761bf79659a185c4a2c40e08934d7ada9e05130e64bd5eb4d634aa', '/etc/cron.d/system_doc_build': 'c7beada82a5a09b29e1db6d9a4c828b3c87c16fb4a405d41d34488898121515e', '/etc/cron.d/system_doc_check': 'aff2cc9afd2078142ca10ab2e1f3012c537f1b170be385b38c7006e396332789', '/etc/systemd/system/tu1nz-bot.service': 'fad12c044b08f691ad1fa6a0afb40c748bfba81b4fbb1ef6240d5a442a213c01', '/usr/local/bin/backup_notify.sh': '878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311', '/usr/local/bin/trendwatch_post.sh': '467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264', '/etc/sudoers': '7b68bd1a3e600364a35ef71bbccfc671735ff840c14ed0a15fad5cebd4020b47', '/etc/sudoers.d/99-dokuagent-pandoc': '485957ca0f803a4f02216ea12625aaa338513bc20195d739c76d9bd993bae97c', '/etc/sudoers.d/chatops-nopass': 'c153102adf2f49433b89db411e87107cc8f2bda2a2c26c2da75cfecaab91388e'}
PATHS=tuple(sorted(set(PATHS)|set(BOUND_BASELINES)|{'/etc/sudoers.d/90-tu1nz-codex-ops','/etc/systemd/system/docker.socket.d/90-tu1nz-root-only.conf'}))
class Refused(Exception):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()

def systemctl(verb,units=(),properties=()):
 if verb not in ('show','cat','list-units','list-unit-files'):raise Refused('non-reading systemd verb')
 if verb in ('show','cat') and not units:raise Refused('empty unit set')
 for name in units:
  if not isinstance(name,str) or not name or len(name)>255 or not re.fullmatch(r'[A-Za-z0-9_.@:\\x-]+',name) or not re.search(r'\.(service|socket|target|mount|automount|timer|path|slice|scope|device|swap)$',name):raise Refused('unit name')
 if verb in ('list-units','list-unit-files') and units:raise Refused('list takes no unit operands')
 if any(p not in PROPS for p in properties):raise Refused('unknown property')
 args=['/usr/bin/systemctl','--no-pager']
 if verb.startswith('list-'):args+=['--all','--plain','--no-legend']
 for p in properties:args+=['-p',p]
 return args+[verb,'--',*units]

def safe_error(raw):
 # Never persist stderr text. Classify known errors and bind all bytes by SHA.
 low=raw.lower()
 return {'bytes':len(raw),'sha256':digest(raw),'labels':[name for name,needle in (('PERMISSION_DENIED',b'permission denied'),('NOT_PERMITTED',b'operation not permitted'),('NOT_FOUND',b'not found'),('INVALID_OPTION',b'invalid option'),('PASSWORD_REQUIRED',b'password is required')) if needle in low]}

def run(args,parser=lambda b:{'bytes':len(b),'sha256':digest(b)},timeout=20,limit=8_000_000,stream=None):
 start=time.monotonic_ns();out=bytearray();err=bytearray();rc=None;timed=False;exception=None;parsed=None;h=hashlib.sha256();size=0;pending=bytearray();events=[]
 try:
  with subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,cwd='/',start_new_session=True) as p:
   sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ,'out');sel.register(p.stderr,selectors.EVENT_READ,'err')
   try:
    while sel.get_map():
     if (time.monotonic_ns()-start)/1e9>=timeout:timed=True;raise TimeoutError()
     for key,_ in sel.select(.1):
      block=os.read(key.fileobj.fileno(),65536)
      if not block:sel.unregister(key.fileobj);continue
      if key.data=='err':
       err.extend(block)
       if len(err)>200_000:raise Refused('stderr bound')
      else:
       h.update(block);size+=len(block)
       if size>limit:raise Refused('stdout bound')
       if stream:
        pending.extend(block)
        if len(pending)>2_000_000 and b'\n' not in pending:raise Refused('line bound')
        while b'\n' in pending:
         line,_,tail=pending.partition(b'\n');pending=bytearray(tail);item=stream(bytes(line))
         if item is not None:events.append(item)
         if len(events)>100000:raise Refused('event bound')
       else:out.extend(block)
    rc=p.wait(timeout=max(.1,timeout-(time.monotonic_ns()-start)/1e9))
    if stream:
     if pending:
      item=stream(bytes(pending))
      if item is not None:events.append(item)
     parsed=events
    else:parsed=parser(bytes(out))
   finally:
    sel.close()
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    rc=p.wait()
 except (KeyboardInterrupt,InterruptedError):raise
 except Exception as e:exception=type(e).__name__;timed=timed or isinstance(e,(TimeoutError,subprocess.TimeoutExpired));parsed=events if stream else None
 return {'command':{'executable':os.path.basename(args[0]),'argv_sha256':digest(encode(args)),'argument_count':len(args)-1},'start_ns':start,'end_ns':time.monotonic_ns(),'returncode':rc,'timeout':timed,'exception_class':exception,'stdout':{'bytes':size,'sha256':h.hexdigest(),'sanitized':parsed},'stderr':safe_error(bytes(err)),'status':'COMPLETE' if rc==0 and not timed and exception is None and not err else 'INCOMPLETE'}

def read_regular(path,limit=32_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0))
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno())
  if not stat.S_ISREG(a.st_mode):raise Refused('not regular')
  raw=f.read(limit+1);z=os.fstat(f.fileno())
  if len(raw)>limit or (a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('read bound or race')
  return raw

def metadata(path,hash_content=True):
 p=Path(path)
 try:s=p.lstat()
 except FileNotFoundError:return {'path':str(p),'absent':True}
 result={'path':str(p),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'dev':s.st_dev,'inode':s.st_ino,'nlink':s.st_nlink,'size':s.st_size,'atime_ns':s.st_atime_ns,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'type':stat.S_IFMT(s.st_mode)}
 result['acl_xattrs']={name:base64.b64encode(os.getxattr(p,name,follow_symlinks=False)).decode() for name in os.listxattr(p,follow_symlinks=False) if 'posix_acl' in name}
 if stat.S_ISLNK(s.st_mode):result['symlink_target']=os.readlink(p)
 if stat.S_ISREG(s.st_mode) and hash_content:
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0));h=hashlib.sha256();count=0
  with os.fdopen(fd,'rb') as f:
   a=os.fstat(f.fileno())
   if (a.st_dev,a.st_ino)!=(s.st_dev,s.st_ino):raise Refused('metadata race')
   while True:
    block=f.read(65536)
    if not block:break
    count+=len(block)
    if count>32_000_000:raise Refused('file size bound')
    h.update(block)
   z=os.fstat(f.fileno())
   if (a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('file changed')
  result['sha256']=h.hexdigest()
 return result

def unit_semantics(raw):
 rows=[];section='';continued=''
 for line in raw.decode('utf8','strict').splitlines():
  if line.endswith('\\'):continued+=line[:-1];continue
  line=continued+line;continued='';line=line.strip()
  if not line or line.startswith(('#',';')):continue
  if line.startswith('['):section=line;continue
  if '=' not in line:raise Refused('unparsed unit line')
  k,v=line.split('=',1);row={'section':section,'directive':k,'value_sha256':digest(v.encode())}
  if k in SAFE_UNIT_VALUES and re.fullmatch(r'[A-Za-z0-9_ :.!@/-]*',v):row['safe_value']=v
  if k.startswith('Exec'):
   try:parts=shlex.split(v);exe=parts[0] if parts else '';row['executable']=exe if re.fullmatch(r'[-+!:@]*/[A-Za-z0-9_./-]+',exe) else 'REDACTED';row['argument_count']=len(parts)-1
   except ValueError:row['parse_error']=True
  rows.append(row)
 if continued:raise Refused('unfinished continuation')
 return {'sha256':digest(raw),'directives':rows}

def properties(raw):
 d={}
 for line in raw.decode().splitlines():
  if not line:continue
  k,sep,v=line.partition('=')
  if not sep or k not in PROPS:raise Refused('unexpected systemd field')
  d[k]=v
 return d

def journal_line(line):
 x=json.loads(line);m=x.get('MESSAGE','');m=m if isinstance(m,str) else ''
 labels=[k for k,p in {'ROOT_OPEN':r'session opened for user root','ROOT_CLOSED':r'session closed for user root','AUTH_FAILURE':r'authentication failure|conversation failed|incorrect password','DAEMON_RELOAD':r'Reloading requested|Reloading finished|daemon-reload','START':r'^Starting |^Started ','STOP':r'^Stopping |^Stopped ','FAILURE':r'Failed with result|Main process exited|Control process exited|Failed to start','EXIT_75':r'status=75|exit.code.*75','OLD_CAPSULE':OLD_SHA,'OLD_TRANSACTION':r'tu1nz-root-only-v9'}.items() if re.search(p,m)]
 ident=x.get('SYSLOG_IDENTIFIER','')
 if not labels and ident not in ('sudo','sshd','systemd'):return None
 row={k:x[k] for k in ('__REALTIME_TIMESTAMP','_BOOT_ID','_PID','_UID','_GID','_SYSTEMD_UNIT','MESSAGE_ID') if k in x}
 row['mychatbuddy_reference']='mychatbuddy-private-alpha' in m
 row['unit_references']=[u for u in UNITS if u in m]
 row['labels']=labels;row['message_sha256']=digest(m.encode());row['identifier']=ident
 if 'COMMAND=' in m:
  exe=m.split('COMMAND=',1)[1].split()[0];row['command_executable']=exe if re.fullmatch(r'/[A-Za-z0-9_./-]{1,150}',exe) else 'REDACTED'
 return row

def docker_projection(raw):
 result=[]
 for c in json.loads(raw):
  s=c['State'];result.append({'id':c['Id'],'name':c['Name'],'image':c['Image'],'state':{k:s.get(k) for k in ('Status','Running','Pid','ExitCode','StartedAt','FinishedAt','OOMKilled')},'health':s.get('Health',{}).get('Status'),'restarts':c['RestartCount'],'config_sha256':digest(encode(c['Config'])),'hostconfig_sha256':digest(encode(c['HostConfig'])),'mounts':c['Mounts'],'networks':c['NetworkSettings']['Networks']})
 return result

def nft_projection(raw):
 def clean(x):
  if isinstance(x,dict):return {k:clean(v) for k,v in x.items() if k not in ('comment','userdata')}
  if isinstance(x,list):return [clean(v) for v in x]
  return x
 return clean(json.loads(raw))

def safe_lines(raw):
 return [{'sha256':digest(l),'bytes':len(l)} for l in raw.splitlines()]

def sudo_projection(raw):
 rows=[]
 for line in raw.decode(errors='strict').splitlines():
  rows.append({'line_sha256':digest(line.encode()),'nopasswd':'NOPASSWD:' in line,'noexec':'NOEXEC:' in line,'no_setenv':'NOSETENV:' in line,'executables':re.findall(r'(?<!\S)/(?:usr/)?(?:s?bin)/[A-Za-z0-9_.-]+',line),'unrestricted_all':bool(re.search(r'\)\s*(?:NOPASSWD:\s*)?ALL\s*$',line))})
 return rows

class Output:
 def __init__(self,path,fixture=False):
  self.path=Path(path);self.files={}
  if fixture:
   if os.geteuid()==0:raise Refused('root fixture forbidden')
  else:
   if os.geteuid()!=0 or self.path!=Path('/var/lib')/TXID:raise Refused('root fixed output only')
   for p in (Path('/'),Path('/var'),Path('/var/lib')):
    s=p.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or any('posix_acl' in n for n in os.listxattr(p)):raise Refused('output ancestry')
  os.mkdir(self.path,0o700);os.chmod(self.path,0o700)
  parent=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(parent);os.close(parent)
  self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def put(self,name,value):
  if not re.fullmatch(r'[a-z0-9_-]+\.json',name):raise Refused('output name')
  if name in self.files and name!='manifest.json':raise Refused('evidence overwrite')
  try:
   s=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
   if name not in self.files or not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise Refused('foreign output')
  except FileNotFoundError:
   if name in self.files:raise Refused('evidence disappeared')
  data=encode(value);tmp='.tmp-'+secrets.token_hex(12);fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  try:
   with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
   os.replace(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd);self.files[name]=digest(data)
  finally:
   try:os.unlink(tmp,dir_fd=self.fd)
   except FileNotFoundError:pass
 def close(self):os.close(self.fd)

class Collector:
 def __init__(self,output):self.output=output;self.sections=[];self.interrupted=False
 def manifest(self,status):
  self.output.put('manifest.json',{'version':VERSION,'transaction_id':TXID,'status':status,'collector_sha256':globals().get('VERIFIED_SOURCE_SHA256'),'sections':self.sections,'files':{k:v for k,v in self.output.files.items() if k!='manifest.json'},'monotonic_ns':time.monotonic_ns(),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 def section(self,name,fn):
  start=time.monotonic_ns();status='COMPLETE';error=None;result=None
  try:
   result=fn()
   def incomplete(x):
    if isinstance(x,dict):return x.get('status')=='INCOMPLETE' or any(incomplete(v) for v in x.values())
    if isinstance(x,list):return any(incomplete(v) for v in x)
    return False
   if incomplete(result):status='INCOMPLETE'
  except (KeyboardInterrupt,InterruptedError) as e:status='INCOMPLETE';error=type(e).__name__;self.interrupted=True
  except Exception as e:status='INCOMPLETE';error=type(e).__name__
  rec={'section':name,'status':status,'start_ns':start,'end_ns':time.monotonic_ns(),'exception_class':error,'result':result}
  self.output.put(name+'.json',rec);self.sections.append({k:rec[k] for k in ('section','status','start_ns','end_ns','exception_class')});self.manifest('INCOMPLETE')
 def execute(self,sections):
  self.manifest('INCOMPLETE')
  for name,fn in sections:
   self.section(name,fn)
   if self.interrupted:break
  status='COMPLETE' if len(self.sections)==len(sections) and all(s['status']=='COMPLETE' for s in self.sections) else 'INCOMPLETE'
  self.manifest(status);return 0 if status=='COMPLETE' else 2

def attempt(fn):
 try:return fn()
 except (KeyboardInterrupt,InterruptedError):raise
 except Exception as e:return {'status':'INCOMPLETE','exception_class':type(e).__name__}

def marker_projection(raw):
 x=json.loads(raw)
 if not isinstance(x,dict):raise Refused('marker shape')
 statuses={'PREPARED','INTENT','DONE','CHECKPOINT','COMPLETED','ROLLED_BACK','ROLLBACK_FAILED','ROOT_STARTED','BACKUP_VERIFIED','INCOMPLETE','FAILED','ABORTED_BEFORE_ROOT_START'}
 phases={'backup','watchdog','install_components','validate_units_sudoers','socket_persistence','clients_before','socket_cutover','root_docker','fresh_chatops_denied','old_contexts_denied','monitoring_containers','remove_membership','remove_unsafe_sudo','quarantines','broker_tests','application_checks','authority_graph','finalize'}
 def one(v):
  r={}
  for k in ('capsule_sha256','collector_sha256','sha256'):
   if isinstance(v.get(k),str) and re.fullmatch('[a-f0-9]{64}',v[k]):r[k]=v[k]
  if v.get('status') in statuses:r['status']=v['status']
  if v.get('phase') in phases:r['phase']=v['phase']
  for k in ('version','deadline_ns','started_ns','finished_ns'):
   if type(v.get(k)) is int:r[k]=v[k]
  if type(v.get('sealed')) is bool:r['sealed']=v['sealed']
  return r
 out=one(x)
 if isinstance(x.get('steps'),list):
  if len(x['steps'])>1000:raise Refused('marker steps bound')
  out['steps']=[one(v) for v in x['steps'] if isinstance(v,dict)]
 return out

def tree_metadata(root,max_entries=2000):
 p=Path(root);result=[];todo=[p]
 while todo:
  q=todo.pop();row=attempt(lambda:metadata(q))
  if row.get('type')==stat.S_IFREG and q.name in ('state.json','manifest.json','checkpoint.json','ROOT_STARTED.json','COMPLETED.json','ROLLED_BACK.json'):
   row['marker']=attempt(lambda:marker_projection(read_regular(q)))
  result.append(row)
  if len(result)>max_entries:result.append({'status':'INCOMPLETE','reason':'ENTRY_BOUND'});break
  if q.is_dir() and not q.is_symlink():todo.extend(sorted(q.iterdir(),reverse=True))
 return result

def artifacts():
 roots=set(ARTIFACT_ROOTS)
 for parent in ('/var/lib','/run','/usr/local/libexec','/etc/systemd/system','/run/systemd/system','/run/systemd/transient'):
  p=Path(parent)
  if p.exists():
   for q in p.iterdir():
    if q.name.startswith(('tu1nz-root-only','tu1nz-codex-ops','tu1nz-mychatbuddy-lifecycle','tu1nz-root-trust','tu1nz-privileged-ops')):roots.add(str(q))
 return {p:attempt(lambda p=p:tree_metadata(p)) for p in sorted(roots)}

def sudo_chain():
 todo=[Path('/etc/sudoers')];seen=set();rows=[]
 while todo:
  p=todo.pop()
  if str(p) in seen:continue
  seen.add(str(p))
  if len(seen)>500:raise Refused('sudo include bound')
  rec=attempt(lambda:metadata(p));rows.append(rec)
  if rec.get('absent') or rec.get('status')=='INCOMPLETE':continue
  if p.is_symlink():rec['status']='INCOMPLETE';rec['reason']='SYMLINK_INCLUDE';continue
  raw=read_regular(p);rec['rules']=sudo_projection(raw)
  for line in raw.decode().splitlines():
   m=re.match(r'^\s*(?:@|#)(include|includedir)\s+(.+)$',line)
   if not m:continue
   parts=shlex.split(m.group(2),comments=True)
   if len(parts)!=1 or '%' in parts[0]:rec['status']='INCOMPLETE';rec['reason']='DYNAMIC_INCLUDE';continue
   q=Path(parts[0]);q=q if q.is_absolute() else p.parent/q
   if m.group(1)=='include':todo.append(q)
   else:
    rec.setdefault('include_directories',[]).append(attempt(lambda:metadata(q,False)))
    try:todo.extend(sorted((x for x in q.iterdir() if '.' not in x.name and not x.name.endswith('~')),reverse=True))
    except OSError:rec['status']='INCOMPLETE';rec['reason']='INCLUDE_DIRECTORY_UNREADABLE'
 return {'files':rows,'visudo':run(['/usr/sbin/visudo','-c'],safe_lines),'effective_chatops':run(['/usr/bin/sudo','-n','-l','-U','chatops'],sudo_projection)}

def processes():
 rows=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   status=dict(l.split(':',1) for l in (p/'status').read_text().splitlines() if ':' in l);uids=list(map(int,status['Uid'].split()));groups=list(map(int,status['Groups'].split()));args=(p/'cmdline').read_bytes()
   related=OLD_SHA.encode() in args or b'tu1nz-root-only-v9' in args
   if 1001 not in uids and not related:continue
   st=(p/'stat').read_text();tail=st[st.rfind(')')+2:].split()
   rows.append({'pid':int(p.name),'ppid':int(status['PPid']),'uids':uids,'gids':list(map(int,status['Gid'].split())),'groups':groups,'start_ticks':int(tail[19]),'related_old_attempt':related,'cmdline_sha256':digest(args),'cgroup_sha256':digest((p/'cgroup').read_bytes())})
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:rows.append({'pid':int(p.name),'status':'INCOMPLETE','reason':'PROCESS_UNREADABLE'})
 return rows

def docker_fds():
 query=run(['/usr/bin/ss','-xaneH'],lambda b:b.decode(),timeout=15)
 if query['status']!='COMPLETE':return query
 text=query['stdout']['sanitized'];query['stdout']['sanitized']=None;ids=set();endpoints=[]
 for line in text.splitlines():
  if '/run/docker.sock' not in line:continue
  m=re.search(r'/run/docker\.sock\s+(\d+)\s+\*\s+(\d+)',line)
  if not m:query['status']='INCOMPLETE';continue
  local,peer=map(int,m.groups());ids.add(local)
  if peer:ids.add(peer)
  endpoints.append({'local_inode':local,'peer_inode':peer,'state':'ESTAB' if 'ESTAB' in line else 'LISTEN' if 'LISTEN' in line else 'OTHER'})
 owners=[];unreadable=[];start=time.monotonic();count=0
 for leader in Path('/proc').iterdir():
  if not leader.name.isdigit():continue
  try:tasks=list((leader/'task').iterdir())
  except FileNotFoundError:continue
  for p in tasks:
   try:
    s=dict(l.split(':',1) for l in (p/'status').read_text().splitlines() if ':' in l)
    for f in (p/'fd').iterdir():
     count+=1
     if count>1_000_000 or time.monotonic()-start>30:raise Refused('FD_SCAN_BOUND')
     try:t=os.readlink(f)
     except FileNotFoundError:continue
     m=re.fullmatch(r'socket:\[(\d+)\]',t)
     if m and int(m.group(1)) in ids:
      st=(p/'stat').read_text();tail=st[st.rfind(')')+2:].split()
      owners.append({'pid':int(p.name),'tgid':int(s['Tgid']),'fd':int(f.name),'inode':int(m.group(1)),'uids':list(map(int,s['Uid'].split())),'gids':list(map(int,s['Gid'].split())),'groups':list(map(int,s['Groups'].split())),'start_ticks':int(tail[19]),'cgroup':(p/'cgroup').read_text().strip()})
   except (FileNotFoundError,ProcessLookupError):continue
   except PermissionError:unreadable.append(int(p.name))
 return {'query':query,'endpoints':endpoints,'owners':owners,'unreadable':unreadable,'unattributed':sorted(ids-{r['inode'] for r in owners}),'status':'COMPLETE' if not unreadable and ids<={r['inode'] for r in owners} else 'INCOMPLETE','snapshot_not_atomic':True}

def unit_record(name):
 q=run(systemctl('show',[name],PROPS),properties)
 data=q['stdout'].get('sanitized') or {};files=[]
 for path in [data.get('FragmentPath',''),data.get('SourcePath','')]+data.get('DropInPaths','').split():
  if not path:continue
  def one(path=path):
   p=Path(path);resolved=p.resolve(strict=True);m=metadata(p)
   if p.is_symlink():m['resolved_metadata']=metadata(resolved)
   m['semantics']=unit_semantics(read_regular(resolved));return m
  files.append(attempt(one))
 return {'properties':q,'files':files}

def containers():
 ids=run(['/usr/bin/docker','--config','/var/empty','--host','unix:///run/docker.sock','ps','-aq','--no-trunc'],lambda b:b.decode().split())
 values=ids['stdout'].get('sanitized') or []
 if ids['status']!='COMPLETE' or any(not re.fullmatch('[a-f0-9]{64}',x) for x in values):return {'list':ids,'status':'INCOMPLETE'}
 return {'list':ids,'inspect':run(['/usr/bin/docker','--config','/var/empty','--host','unix:///run/docker.sock','inspect',*values],docker_projection,timeout=30)} if values else {'list':ids,'containers':[]}

def audit_history():
 results=[];begin=1790560800;end=1790614800
 for p in sorted(Path('/var/log/audit').glob('audit.log*')):
  def read_one(p=p):
   import gzip
   opener=gzip.open if p.suffix=='.gz' else open;count=0;first=None;last=None;selected=[];start=time.monotonic()
   with opener(p,'rt',errors='replace') as f:
    for line in f:
     count+=1
     if count>2_000_000 or time.monotonic()-start>20:raise Refused('AUDIT_BOUND')
     m=re.search(r'type=(\w+) msg=audit\(([0-9.]+):(\d+)\)',line)
     if not m:continue
     typ,ts,event=m.groups();ts=float(ts);first=ts if first is None else first;last=ts
     if not begin<=ts<=end:continue
     if typ in ('SYSCALL','USER_CMD','USER_START','USER_END','EXECVE','PATH','PROCTITLE'):
      flags={'old_capsule_literal':OLD_SHA in line,'old_transaction_literal':'tu1nz-root-only-v9' in line,'mycb_unit_literal':'mychatbuddy-private-alpha.service' in line}
      # Decode hex proctitles/exec strings only to match fixed markers; never export them.
      for h in re.findall(r'\b(?:proctitle|cmd|a\d+)=([0-9A-Fa-f]{8,})\b',line):
       if len(h)>2_000_000:raise Refused('AUDIT_HEX_BOUND')
       decoded=bytes.fromhex(h)
       flags['old_capsule_literal']|=OLD_SHA.encode() in decoded;flags['old_transaction_literal']|=b'tu1nz-root-only-v9' in decoded;flags['mycb_unit_literal']|=b'mychatbuddy-private-alpha.service' in decoded
      if any(flags.values()) or 1790608515<=ts<=1790608525:
       selected.append({'type':typ,'time':ts,'event':event,'flags':flags,'fields':dict(re.findall(r'\b(pid|ppid|uid|euid|syscall|success|exit)=([A-Za-z0-9_-]+)',line))})
       if len(selected)>20000:raise Refused('AUDIT_RESULT_BOUND')
   return {'file':str(p),'first':first,'last':last,'records':count,'selected':selected}
  results.append(attempt(read_one))
 return results

def python_identity():
 paths={Path(sys.executable),Path('/usr/bin/python3').resolve()}
 rows=[attempt(lambda p=p:metadata(p)) for p in paths]
 cache=Path(sys.base_prefix)/('lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))/'__pycache__'
 # Current cache metadata is evidence; without a prior binding it is not history.
 return {'version':sys.version,'executable':sys.executable,'files':rows,'historical_binary_digest':'UNBOUND','stdlib_cache':attempt(lambda:tree_metadata(cache,1000))}

def semantic_diff(previous,current):
 def group(x):
  d={}
  for row in x['directives']:d.setdefault((row['section'],row['directive']),[]).append(row)
  return d
 a=group(previous);b=group(current);changes=[]
 for k in sorted(set(a)|set(b)):
  if a.get(k)!=b.get(k):changes.append({'section':k[0],'directive':k[1],'before':a.get(k,[]),'after':b.get(k,[])})
 for change in changes:change['metadata_only']=change['directive'] in ('Documentation','Description')
 understood=bool(changes) and all(change['metadata_only'] or all('safe_value' in r for v in (change['before'],change['after']) for r in v) for change in changes)
 return {'classification':'FOREIGN_CHANGE_SEMANTICS_KNOWN_ACTOR_UNKNOWN' if understood else 'FOREIGN_CHANGE_UNRESOLVED','changes':changes,'actor':'UNATTRIBUTED','prior_sha256':previous['sha256'],'current_sha256':current['sha256'],'no_actor_inference_from_timestamps':True}

def mycb_record():
 record=unit_record('mychatbuddy-private-alpha.service')
 primary=next((f for f in record['files'] if f.get('path')==record['properties'].get('stdout',{}).get('sanitized',{}).get('FragmentPath')),None)
 record['prior']=PRIOR_UNIT
 record['git_candidate']=attempt(lambda:metadata('/opt/tu1nz_repos/control/managed/systemd/mychatbuddy-private-alpha.service'))
 record['git_candidate_matches_current']=bool(primary and primary.get('sha256') and primary.get('sha256')==record['git_candidate'].get('sha256'))
 record['git_provenance_pre_read']={'commit':'9b383960291da469671c3888cfa4fdcc3c33cf01','reference_sha256':'e9f6b2e0fddb430673843b628cdde9e7d472979480e04a7753c365de8c45c976','actor':'UNATTRIBUTED'}
 record['semantic_diff']=semantic_diff(PRIOR_UNIT,primary['semantics']) if primary and 'semantics' in primary else {'classification':'FOREIGN_CHANGE_UNRESOLVED'}
 record['known_previous_exit_utc']='2026-09-28T01:12:34Z'
 record['known_root_session_open_utc']='2026-09-28T15:15:18.857100Z'
 record['historical_times_require_journal_corroboration']=True
 return record

def inventory_projection(raw):
 rows=[]
 for line in raw.decode().splitlines():
  fields=line.split()
  if not fields:continue
  # Description text is deliberately omitted; only unit identity and state columns.
  if not re.fullmatch(r'[A-Za-z0-9_.@:\\x-]+',fields[0]):raise Refused('inventory unit encoding')
  rows.append(fields[:4])
 return rows

def bound_files():
 rows=[]
 for p in PATHS:
  row=attempt(lambda p=p:metadata(p))
  row['expected_sha256']=BOUND_BASELINES.get(p)
  if p in BOUND_BASELINES:row['matches_bound_prestate']=row.get('sha256')==BOUND_BASELINES[p]
  rows.append(row)
 return rows

def fail2ban_record():
 def status(raw):
  text=raw.decode();counts={}
  for line in text.splitlines():
   m=re.search(r'(Currently failed|Total failed|Currently banned|Total banned):\s*(\d+)',line)
   if m:counts[m[1]]=int(m[2])
  return {'counts':counts,'line_hashes':safe_lines(raw)}
 result={'sshd':run(['/usr/bin/fail2ban-client','status','sshd'],status)}
 # This fixed getter exposes the configured port without evaluating any action.
 result['actions']=run(['/usr/bin/fail2ban-client','get','sshd','actions'],lambda b:{'names':re.findall(r'^[ \t]*-?[ \t]*([A-Za-z0-9_-]+)[ \t]*$',b.decode(),re.M),'hashes':safe_lines(b)})
 names=(result['actions'].get('stdout',{}).get('sanitized') or {}).get('names',[])
 result['ports']={n:run(['/usr/bin/fail2ban-client','get','sshd','action',n,'port'],lambda b:{'port':b.decode().strip()} if re.fullmatch(rb'[0-9,: \r\n-]+',b) else {'unparsed_sha256':digest(b)}) for n in names if n not in ('actions','sshd')}
 return result

def section_plan():
 sections=[('run',lambda:{'version':VERSION,'transaction_id':TXID,'old_capsule_sha256':OLD_SHA,'uid':os.geteuid(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}),('python',python_identity),('artifacts',artifacts),('sudoers',sudo_chain),('accounts',lambda:{'files':[attempt(lambda p=p:metadata(p)) for p in ('/etc/group','/etc/gshadow')],'chatops':{'uid':pwd.getpwnam('chatops').pw_uid,'gid':pwd.getpwnam('chatops').pw_gid,'groups':os.getgrouplist('chatops',pwd.getpwnam('chatops').pw_gid)},'group_memberships':[{'name':g.gr_name,'gid':g.gr_gid,'members':g.gr_mem} for g in grp.getgrall()]}),('processes',processes),('socket',lambda:{'metadata':[metadata('/run/docker.sock'),metadata('/var/run/docker.sock')],'clients':docker_fds()}),('files',bound_files),('unit_inventory',lambda:run(systemctl('list-units'),inventory_projection)),('unit_file_inventory',lambda:run(systemctl('list-unit-files'),inventory_projection)),('containers',containers),('nftables',lambda:run(['/usr/sbin/nft','-j','-a','list','ruleset'],nft_projection)),('ufw',lambda:run(['/usr/sbin/ufw','status','verbose'],safe_lines)),('sshd',lambda:run(['/usr/sbin/sshd','-T'],lambda b:{'lines':safe_lines(b),'safe_effective':{k:v for l in b.decode().splitlines() for k,_,v in [l.partition(' ')] if k in ('port','listenaddress','permitrootlogin','passwordauthentication','pubkeyauthentication','authenticationmethods','allowusers','allowgroups','denyusers','denygroups','usepam','kbdinteractiveauthentication')}})),('fail2ban',fail2ban_record),('audit',audit_history),('mychatbuddy',mycb_record),('supporting_paths',lambda:{p:attempt(lambda p=p:tree_metadata(p,3000)) for p in ('/etc/systemd/system/docker.service.d','/etc/systemd/system/docker.socket.d','/etc/ssh/sshd_config.d','/etc/fail2ban/jail.d','/etc/fail2ban/action.d','/var/lib/tu1nz-backup-notify-quarantine','/var/lib/tu1nz-root-trust','/var/lib/tausendunde1nz/agentmode')})]
 for i,u in enumerate(UNITS):sections.append(('unit_'+str(i),lambda u=u:unit_record(u)))
 # Hourly windows retain independent partial results and bound each command.
 start=datetime.datetime(2026,9,28,0,tzinfo=datetime.timezone.utc);now=datetime.datetime.now(datetime.timezone.utc)
 for i in range(min(72,int((now-start).total_seconds()//3600)+1)):
  a=start+datetime.timedelta(hours=i);b=a+datetime.timedelta(hours=1)
  sections.append(('journal_'+str(i),lambda a=a,b=b:run(['/usr/bin/journalctl','--no-pager','--since',a.isoformat(),'--until',b.isoformat(),'-o','json'],timeout=30,limit=100_000_000,stream=journal_line)))
 if (now-start).total_seconds()>72*3600:sections.append(('journal_coverage_gap',lambda:{'status':'INCOMPLETE','reason':'WINDOW_LIMIT'}))
 return sections

def export_results(output):
 # Sanitized records only. No raw journal/unit/credential/environment text exists
 # in this directory. Export over the authenticated SSH stdout channel so later
 # analysis does not require a second sudo invocation or relaxed root ACLs.
 import gzip
 records={}
 for name,sha in output.files.items():
  raw=read_regular(output.path/name)
  if digest(raw)!=sha:raise Refused('result changed before export')
  records[name]={'sha256':sha,'value':json.loads(raw)}
 return base64.b64encode(gzip.compress(encode(records),mtime=0)).decode()

def main():
 output=None;collector=None
 def interrupt(sig,frame):raise InterruptedError('interrupted')
 try:
  if not sys.dont_write_bytecode:raise Refused('interpreter must use -B')
  if os.geteuid()!=0 or not re.fullmatch(r'[a-f0-9]{64}',globals().get('VERIFIED_SOURCE_SHA256','')):raise Refused('verified root entry required')
  os.umask(0o077);sys.dont_write_bytecode=True
  output=Output(Path('/var/lib')/TXID);collector=Collector(output)
  signal.signal(signal.SIGINT,interrupt);signal.signal(signal.SIGTERM,interrupt)
  rc=collector.execute(section_plan())
  print('V10_SANITIZED_EVIDENCE_GZIP_BASE64='+export_results(output))
  print(json.dumps({'classification':'UNRESOLVED','control_flow':CONTROL_FLOW,'status':'COMPLETE' if rc==0 else 'INCOMPLETE','transaction_id':TXID,'output':str(output.path),'manifest_sha256':output.files['manifest.json']}));return rc
 except BaseException as e:
  if collector:
   try:collector.manifest('INCOMPLETE')
   except Exception:pass
  print(json.dumps({'status':'INCOMPLETE' if output else 'FAILED','error_class':type(e).__name__,'transaction_id':TXID}));return 2 if output else 70
 finally:
  if output:output.close()

if __name__=='__main__':raise SystemExit(main())
