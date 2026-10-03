"""Internal action IDs, constant argv, stored and independently loaded proof.

The supplied Manager has its own fixed transport allowlist. Files are the
declared phase-0 backend, never a pathname selected from persisted input.
"""
from anchor import Refused, digest, encode

ACTIONS = {
 'RELOAD': ('daemon-reload', None),
 'ANCHOR_START': ('start', 'anchor'),
 'ANCHOR_ENABLE': ('enable', 'anchor'),
 'WATCH_START': ('start', 'watch'),
 'WATCH_STOP': ('stop', 'watch'),
 'WATCH_ENABLE': ('enable', 'watch'),
 'WATCH_DISABLE': ('disable', 'watch'),
}

class Adapter:
 def __init__(self, manager, files, store=None):
  self.manager=manager; self.files=files;self.store=store
 def stored(self):
  return self.files.snapshot(self.files.targets, self.files.directories)
 def perform(self, action):
  if type(action)!=str or action not in ACTIONS:raise Refused('INTERNAL_ACTION_ID')
  verb,role=ACTIONS[action];m=self.manager
  try:
   stored=self.stored();before={r:m.show(r) for r in ('anchor','watch','consumer')}
   if before['consumer']['ActiveState']!='inactive':raise Refused('ADAPTER_CONSUMER_ACTIVE')
   if role and verb in ('start','enable') and before[role]['LoadState']!='loaded':raise Refused('ADAPTER_PRESTATE')
   if role and verb=='stop' and before[role]['ActiveState'] not in ('active','activating','deactivating','inactive','failed'):raise Refused('ADAPTER_PRESTATE')
   m.record({'operation':'FIXED_ADAPTER','action':action,'state':'INTENT','stored_sha256':digest(encode(stored)),'loaded_sha256':digest(encode(before))})
   m.action(verb,role)
   # Manager action already checks exit/timeout and loaded postconditions.
   # Re-read both evidence sources; rc=0 never substitutes for either.
   after_stored=self.stored();after={r:m.show(r) for r in before}
   if after_stored!=stored:raise Refused('ADAPTER_STORED_DRIFT')
   if any(v['NeedDaemonReload']!='no' for v in after.values()):raise Refused('ADAPTER_LOADED_DRIFT')
   if after['consumer']['ActiveState']!='inactive':raise Refused('ADAPTER_CONSUMER_ACTIVE')
   if self.store is not None:
    m.verify(digest(self.store.read('base.json')),self.store.base()['interpreter'])
   elif verb!='daemon-reload':
    for r in before:
     if any(after[r][k]!=before[r][k] for k in ('Id','FragmentPath','DropInPaths','ExecStart','ExecCondition','Requires','After','Before','User','Group','UMask','PrivateNetwork','NoNewPrivileges')):raise Refused('ADAPTER_LOADED_CONFIGURATION_DRIFT')
   m.record({'operation':'FIXED_ADAPTER','action':action,'state':'DONE','stored_sha256':digest(encode(after_stored)),'loaded_sha256':digest(encode(after))})
   return after
  except BaseException:
   m.close();raise

class BoundManager:
 """Installer compatibility facade; caller cannot supply an extra command."""
 def __init__(self,manager,files,store=None):self.raw=manager;self.adapter=Adapter(manager,files,store)
 def action(self,verb,role=None):
  ids=[k for k,v in ACTIONS.items() if v==(verb,role)]
  if len(ids)!=1:raise Refused('BOUND_ADAPTER_SCOPE')
  return self.adapter.perform(ids[0])
 def show(self,role):return self.raw.show(role)
 def verify(self,*args):return self.raw.verify(*args)
 def call(self,args):return self.raw.call(args)
