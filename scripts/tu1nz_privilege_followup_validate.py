"""Private evidence integrity validator; never emits raw collected contents."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def validate(root,commit,source_sha):
 root=Path(root);s=root.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('directory_mode')
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def read(name):
  if not re.fullmatch(r'[a-z0-9_-]+\.(?:json|bin)',name):raise ValueError('filename')
  child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  with os.fdopen(child,'rb') as f:
   s=os.fstat(f.fileno())
   if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600:raise ValueError('file_metadata')
   return f.read()
 try:
  manifest=json.loads(read('manifest.json'))
  if manifest['expected_commit']!=commit or manifest['script_sha256']!=source_sha:raise ValueError('binding')
  hashes=manifest['file_hashes']
  if set(os.listdir(fd))!=set(hashes)|{'manifest.json'}:raise ValueError('unlisted_file')
  for name,expected in hashes.items():
   if hashlib.sha256(read(name)).hexdigest()!=expected:raise ValueError('checksum')
  return {'integrity_valid':True,'files':len(hashes),'collection_finished':manifest.get('collection_finished',False),
          'status':manifest['status'],'review_required':True}
 finally:os.close(fd)
