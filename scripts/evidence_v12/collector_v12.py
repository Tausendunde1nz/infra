"""TU1NZ V12: fixed read-only evidence; no deployment or mutation operations.
DB/WAL exist solely in memory. Persistent artifacts contain only reduced evidence.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import sqlite3
import stat
import struct
import sys
import subprocess
import time
import types

CONTAINER='e2473c1d0a106b515eee5e63984260046beae22b16724af281368f32c7bd69c7'
IMAGE='sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'
DB=Path('/opt/n8n/data/database.sqlite')
LIMIT=128*1024*1024
APPARMOR_SOURCE_B64='IiIiRml4ZWQsIHJlYWQtb25seSBjb2xsZWN0b3IgZm9yIGxhdGVyIGJvdW5kIHJvb3Qgc3RhZ2luZy4gTm8gYWN0aXZhdGlvbiBDTEkuCgpSZXR1cm5zIHNhbml0aXplZCBkYXRhIHRvIHRoZSB0cmFuc2FjdGlvbidzIHByaXZhdGUgYXRvbWljIGV2aWRlbmNlIHdyaXRlci4KRG9lcyBub3QgbG9hZCwgY29tcGlsZSwgY2hhbmdlLCBhcHBseSBvciBpbnRlcnByZXQgYSBwb2xpY3kgb3IgYXBwbGljYXRpb24uCiIiIgppbXBvcnQgaGFzaGxpYgppbXBvcnQgaHR0cC5jbGllbnQKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aAppbXBvcnQgcmUKaW1wb3J0IHNvY2tldAppbXBvcnQgc3RhdAoKQ09OVEFJTkVSPSdlMjQ3M2MxZDBhMTA2YjUxNWVlZTVlNjM5ODQyNjAwNDZiZWFlMjJiMTY3MjRhZjI4MTM2OGYzMmM3YmQ2OWM3JwpJTUFHRT0nc2hhMjU2OmYwYzdjNjE5YjQ1ZmZiNDc1ZDc5YzIzMzlmYmVmMjFjZWQwM2M2ZTgzZDkxOWQzMjFlZjg5YjQwY2Q0ODg5ZGInClBPTElDWT0nZGY0YWY0Y2EyOTBmZDAzMjM3YTdlNTBiNjc0YmY5YjNjMjNmYmJjMWZkOGUxODcwMjczMDc3OGM5MjQ0N2QwYScKU0VDVVJJVFk9UGF0aCgnL3N5cy9rZXJuZWwvc2VjdXJpdHkvYXBwYXJtb3InKQpTT1VSQ0U9UGF0aCgnL2V0Yy9hcHBhcm1vci5kJykKCmNsYXNzIFJlZnVzZWQoUnVudGltZUVycm9yKTpwYXNzCgpkZWYgZGlnZXN0KGRhdGEpOnJldHVybiBoYXNobGliLnNoYTI1NihkYXRhKS5oZXhkaWdlc3QoKQoKY2xhc3MgVW5peChodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbik6CiAgICBkZWYgY29ubmVjdChzZWxmKToKICAgICAgICBzZWxmLnNvY2s9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfVU5JWCxzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgc2VsZi5zb2NrLnNldHRpbWVvdXQoMTUpO3NlbGYuc29jay5jb25uZWN0KCcvcnVuL2RvY2tlci5zb2NrJykKCmRlZiBkb2NrZXJfZ2V0KHBhdGgpOgogICAgaWYgcGF0aCBub3QgaW4gKCcvdmVyc2lvbicsJy9jb250YWluZXJzLycrQ09OVEFJTkVSKycvanNvbicpOnJhaXNlIFJlZnVzZWQoJ2RvY2tlcl9wYXRoJykKICAgIGM9VW5peCgnbG9jYWxob3N0Jyx0aW1lb3V0PTE1KQogICAgdHJ5OgogICAgICAgIGMucmVxdWVzdCgnR0VUJyxwYXRoKTtyPWMuZ2V0cmVzcG9uc2UoKTtiPXIucmVhZCgyXzAwMF8wMDEpCiAgICAgICAgaWYgci5zdGF0dXMhPTIwMCBvciBsZW4oYik+Ml8wMDBfMDAwOnJhaXNlIFJlZnVzZWQoJ2RvY2tlcl9yZXNwb25zZScpCiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoYikKICAgIGZpbmFsbHk6Yy5jbG9zZSgpCgpkZWYgcmVhZChwYXRoLGxpbWl0PTFfMDAwXzAwMCk6CiAgICBmZD1vcy5vcGVuKHBhdGgsb3MuT19SRE9OTFl8b3MuT19OT05CTE9DSykKICAgIHdpdGggb3MuZmRvcGVuKGZkLCdyYicpIGFzIGY6CiAgICAgICAgYmVmb3JlPW9zLmZzdGF0KGYuZmlsZW5vKCkpO2I9Zi5yZWFkKGxpbWl0KzEpO2FmdGVyPW9zLmZzdGF0KGYuZmlsZW5vKCkpCiAgICBpZiBsZW4oYik+bGltaXQ6cmFpc2UgUmVmdXNlZCgncmVhZF9saW1pdCcpCiAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKGJlZm9yZS5zdF9tb2RlKTpyYWlzZSBSZWZ1c2VkKCdmaWxlX3R5cGUnKQogICAgaWYgKGJlZm9yZS5zdF9kZXYsYmVmb3JlLnN0X2lubyxiZWZvcmUuc3RfbXRpbWVfbnMsYmVmb3JlLnN0X2N0aW1lX25zKSE9KGFmdGVyLnN0X2RldixhZnRlci5zdF9pbm8sYWZ0ZXIuc3RfbXRpbWVfbnMsYWZ0ZXIuc3RfY3RpbWVfbnMpOnJhaXNlIFJlZnVzZWQoJ3JlYWRfZHJpZnQnKQogICAgcmV0dXJuIGIKCmRlZiBpZGVudGl0eShjKToKICAgIGlmIGNbJ0lkJ10hPUNPTlRBSU5FUiBvciBjWydJbWFnZSddIT1JTUFHRSBvciBub3QgY1snU3RhdGUnXVsnUnVubmluZyddOnJhaXNlIFJlZnVzZWQoJ2NvbnRhaW5lcl9kcmlmdCcpCiAgICBwaWQ9Y1snU3RhdGUnXVsnUGlkJ10KICAgIGlmIHR5cGUocGlkKSBpcyBub3QgaW50IG9yIHBpZDw9MTpyYWlzZSBSZWZ1c2VkKCdwaWQnKQogICAgcmV0dXJuIChjWydJZCddLGNbJ0ltYWdlJ10scGlkLGNbJ1N0YXRlJ11bJ1N0YXJ0ZWRBdCddLGMuZ2V0KCdBcHBBcm1vclByb2ZpbGUnKSkKCmRlZiBpbmNsdWRlX25hbWVzKHRleHQpOgogICAgcmVzdWx0PVtdCiAgICBmb3IgbGluZSBpbiB0ZXh0LnNwbGl0bGluZXMoKToKICAgICAgICBpZiByZS5tYXRjaChyJ15ccyojP2luY2x1ZGVcYicsbGluZSk6CiAgICAgICAgICAgIG09cmUuZnVsbG1hdGNoKHInXHMqIz9pbmNsdWRlXHMrKD86aWYgZXhpc3RzXHMrKT9bPCJdKFtBLVphLXowLTlfLi8tXSspWz4iXVxzKicsbGluZSkKICAgICAgICAgICAgaWYgbm90IG06cmFpc2UgUmVmdXNlZCgndW5yZXNvbHZlZF9pbmNsdWRlX3N5bnRheCcpCiAgICAgICAgICAgIHZhbHVlPW0uZ3JvdXAoMSkKICAgICAgICAgICAgaWYgdmFsdWUuc3RhcnRzd2l0aCgnLycpIG9yICcuLicgaW4gdmFsdWUuc3BsaXQoJy8nKTpyYWlzZSBSZWZ1c2VkKCdpbmNsdWRlX2VzY2FwZScpCiAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQodmFsdWUpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgc291cmNlX3JlY29yZHMoKToKICAgIHRvZG89W1NPVVJDRS8nZG9ja2VyJyxTT1VSQ0UvJ2RvY2tlci1kZWZhdWx0J107c2Vlbj1zZXQoKTtyZXN1bHQ9W10KICAgIHdoaWxlIHRvZG86CiAgICAgICAgcD10b2RvLnBvcCgpCiAgICAgICAgaWYgcCBpbiBzZWVuOmNvbnRpbnVlCiAgICAgICAgc2Vlbi5hZGQocCkKICAgICAgICBpZiBsZW4oc2Vlbik+NjQ6cmFpc2UgUmVmdXNlZCgnaW5jbHVkZV9ib3VuZCcpCiAgICAgICAgaWYgbm90IHAuZXhpc3RzKCk6CiAgICAgICAgICAgIGlmIHAuaXNfc3ltbGluaygpOnJhaXNlIFJlZnVzZWQoJ3NvdXJjZV9zeW1saW5rJykKICAgICAgICAgICAgcmVzdWx0LmFwcGVuZCh7J3BhdGgnOnN0cihwKSwnYWJzZW50JzpUcnVlfSk7Y29udGludWUKICAgICAgICBmb3IgcGFyZW50IGluIFtwLCpwLnBhcmVudHNdOgogICAgICAgICAgICBzPXBhcmVudC5sc3RhdCgpCiAgICAgICAgICAgIGlmIHN0YXQuU19JU0xOSyhzLnN0X21vZGUpIG9yIHMuc3RfdWlkIT0wIG9yIHMuc3RfbW9kZSYwbzAyMjpyYWlzZSBSZWZ1c2VkKCdzb3VyY2VfdHJ1c3QnKQogICAgICAgICAgICBpZiBhbnkoJ3Bvc2l4X2FjbCcgaW4geCBmb3IgeCBpbiBvcy5saXN0eGF0dHIocGFyZW50LGZvbGxvd19zeW1saW5rcz1GYWxzZSkpOnJhaXNlIFJlZnVzZWQoJ3NvdXJjZV9hY2wnKQogICAgICAgIGI9cmVhZChwLDI2MjE0NCk7dGV4dD1iLmRlY29kZSgndXRmLTgnKTtpbmNsdWRlcz1pbmNsdWRlX25hbWVzKHRleHQpCiAgICAgICAgcmVzdWx0LmFwcGVuZCh7J3BhdGgnOnN0cihwKSwnc2hhMjU2JzpkaWdlc3QoYiksJ3RleHQnOnRleHQsJ2luY2x1ZGVzJzppbmNsdWRlcywKICAgICAgICAgICAgICAgICAgICAgICAnZWZmZWN0aXZlX2tlcm5lbF9zb3VyY2VfcHJvdmVuJzpGYWxzZX0pCiAgICAgICAgdG9kby5leHRlbmQoU09VUkNFL3ggZm9yIHggaW4gaW5jbHVkZXMpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgc2VjdXJpdHlfZmlsZShwLHJhdz1GYWxzZSk6CiAgICBpZiBTRUNVUklUWSBub3QgaW4gcC5yZXNvbHZlKCkucGFyZW50czpyYWlzZSBSZWZ1c2VkKCdzZWN1cml0eWZzX2VzY2FwZScpCiAgICB0cnk6CiAgICAgICAgYj1yZWFkKHAsNjQqMTAyNCoxMDI0IGlmIHJhdyBlbHNlIDI2MjE0NCkKICAgICAgICBvdXQ9eydwYXRoJzpzdHIocCksJ3NoYTI1Nic6ZGlnZXN0KGIpLCdieXRlcyc6bGVuKGIpfQogICAgICAgIGlmIG5vdCByYXc6b3V0Wyd0ZXh0J109Yi5kZWNvZGUoJ3V0Zi04JykKICAgICAgICByZXR1cm4gb3V0CiAgICBleGNlcHQgUGVybWlzc2lvbkVycm9yOnJldHVybiB7J3BhdGgnOnN0cihwKSwnc3RhdHVzJzonRUFDQ0VTJ30KCmRlZiBjb2xsZWN0KCk6CiAgICBpZiBvcy5nZXRldWlkKCkhPTA6cmFpc2UgUmVmdXNlZCgncm9vdF9yZXF1aXJlZCcpCiAgICBjPWRvY2tlcl9nZXQoJy9jb250YWluZXJzLycrQ09OVEFJTkVSKycvanNvbicpO2JlZm9yZT1pZGVudGl0eShjKTtwaWQ9YmVmb3JlWzJdCiAgICBhdHRyPXJlYWQoJy9wcm9jLyVzL2F0dHIvY3VycmVudCclcGlkLDQwOTYpLmRlY29kZSgpLnN0cmlwKCkKICAgIGlmIGF0dHIhPSdkb2NrZXItZGVmYXVsdCAoZW5mb3JjZSknIG9yIGJlZm9yZVs0XSE9J2RvY2tlci1kZWZhdWx0JzpyYWlzZSBSZWZ1c2VkKCdwcm9maWxlX21hcHBpbmcnKQogICAgIyBEaXJlY3RvcmllcyBhcmUga2VybmVsLWdlbmVyYXRlZC4gT25seSB0aGUgb25lIGZpeGVkIHByb2ZpbGUgbWF5IG1hdGNoLgogICAgcHJvZmlsZXM9W3AgZm9yIHAgaW4gKFNFQ1VSSVRZLydwb2xpY3kvcHJvZmlsZXMnKS5pdGVyZGlyKCkgaWYgcmUuZnVsbG1hdGNoKHInZG9ja2VyLWRlZmF1bHRcLlswLTldKycscC5uYW1lKV0KICAgIGlmIGxlbihwcm9maWxlcykhPTE6cmFpc2UgUmVmdXNlZCgncHJvZmlsZV9jb3VudCcpCiAgICBwcm9maWxlPXByb2ZpbGVzWzBdCiAgICBpZiByZWFkKHByb2ZpbGUvJ3NoYTI1NicpLmRlY29kZSgpLnN0cmlwKCkhPVBPTElDWTpyYWlzZSBSZWZ1c2VkKCdwb2xpY3lfZHJpZnQnKQogICAgdHJ5OnNvdXJjZXM9c291cmNlX3JlY29yZHMoKQogICAgZXhjZXB0IChPU0Vycm9yLFVuaWNvZGVFcnJvcixSZWZ1c2VkKSBhcyBlOgogICAgICAgIHNvdXJjZXM9W3snc3RhdHVzJzonU09VUkNFX0VYUE9SVF9MSU1JVEVEJywnZXJyb3JfY2xhc3MnOnR5cGUoZSkuX19uYW1lX199XQogICAgcmVzdWx0PXsnY29udGFpbmVyJzpDT05UQUlORVIsJ2ltYWdlJzpJTUFHRSwncGlkJzpwaWQsJ2F0dHJfY3VycmVudCc6YXR0ciwKICAgICAgICAgICAgJ3NlY3VyaXR5X29wdGlvbnMnOmNbJ0hvc3RDb25maWcnXS5nZXQoJ1NlY3VyaXR5T3B0JyksCiAgICAgICAgICAgICdkb2NrZXJfdmVyc2lvbic6e2s6diBmb3Igayx2IGluIGRvY2tlcl9nZXQoJy92ZXJzaW9uJykuaXRlbXMoKSBpZiBrIGluICgnVmVyc2lvbicsJ0FwaVZlcnNpb24nLCdNaW5BUElWZXJzaW9uJywnR2l0Q29tbWl0JywnT3MnLCdBcmNoJyl9LAogICAgICAgICAgICAncHJvZmlsZSc6W3NlY3VyaXR5X2ZpbGUocHJvZmlsZS9uLG49PSdyYXdfZGF0YScpIGZvciBuIGluICgnbmFtZScsJ21vZGUnLCdzaGEyNTYnLCdyYXdfYWJpJywncmF3X3NoYTI1NicsJ3Jhd19kYXRhJyldLAogICAgICAgICAgICAnc291cmNlcyc6c291cmNlcywnZmVhdHVyZXMnOltdfQogICAgZW50cmllcz1zb3J0ZWQoKFNFQ1VSSVRZLydmZWF0dXJlcycpLnJnbG9iKCcqJykpCiAgICBpZiBsZW4oZW50cmllcyk+MTAyNDpyYWlzZSBSZWZ1c2VkKCdmZWF0dXJlX2JvdW5kJykKICAgIGZvciBwIGluIGVudHJpZXM6CiAgICAgICAgaWYgcC5pc19zeW1saW5rKCk6cmFpc2UgUmVmdXNlZCgnZmVhdHVyZV9zeW1saW5rJykKICAgICAgICBpZiBwLmlzX2ZpbGUoKTpyZXN1bHRbJ2ZlYXR1cmVzJ10uYXBwZW5kKHNlY3VyaXR5X2ZpbGUocCkpCiAgICBpZiBpZGVudGl0eShkb2NrZXJfZ2V0KCcvY29udGFpbmVycy8nK0NPTlRBSU5FUisnL2pzb24nKSkhPWJlZm9yZTpyYWlzZSBSZWZ1c2VkKCdjb250YWluZXJfcmFjZScpCiAgICBpZiByZWFkKCcvcHJvYy8lcy9hdHRyL2N1cnJlbnQnJXBpZCw0MDk2KS5kZWNvZGUoKS5zdHJpcCgpIT1hdHRyOnJhaXNlIFJlZnVzZWQoJ3Byb2ZpbGVfcmFjZScpCiAgICBpZiByZWFkKHByb2ZpbGUvJ3NoYTI1NicpLmRlY29kZSgpLnN0cmlwKCkhPVBPTElDWTpyYWlzZSBSZWZ1c2VkKCdwb2xpY3lfcmFjZScpCiAgICByZXN1bHRbJ2h1bWFuX3JlYWRhYmxlX2VmZmVjdGl2ZV9wb2xpY3knXT0nTk9UX1BST1ZFTl9CWV9SQVdfQklOQVJZX09SX0RJU0tfU09VUkNFJwogICAgcmVzdWx0WydmdXJ0aGVyX2dlbmVyYWxfY29sbGVjdG9yX2F1dGhvcml6ZWQnXT1GYWxzZQogICAgcmV0dXJuIHJlc3VsdAo='
APPARMOR_SHA256='cc7c4a4b45002f2da5906f9aaa3652dae6624cf6df658d3e02f484e42f71f586'
CONFIGS=('/etc/nginx/sites-enabled/tu1nz.conf',)
class Refused(RuntimeError):pass

def sha(b):return hashlib.sha256(b).hexdigest()
def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()

def read(path,limit=LIMIT,owner=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 if not stat.S_ISREG(os.fstat(fd).st_mode):
  os.close(fd);raise Refused('READ_TYPE')
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno())
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise Refused('READ_TYPE_SIZE')
  if owner is not None and a.st_uid!=owner:raise Refused('READ_OWNER')
  b=f.read(limit+1);z=os.fstat(f.fileno())
 key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))
 if len(b)>limit or key(a)!=key(z):raise Refused('READ_DRIFT')
 return b,{'identity':key(a),'sha256':sha(b)}

def command(args,timeout=15,limit=8*1024*1024):
 """Fixed caller argv; bounded streaming; full process-group cleanup on timeout."""
 p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},start_new_session=True)
 sel=selectors.DefaultSelector();out=bytearray();err=bytearray();start=time.monotonic_ns()
 for f,key in ((p.stdout,'out'),(p.stderr,'err')):os.set_blocking(f.fileno(),False);sel.register(f,selectors.EVENT_READ,key)
 try:
  while sel.get_map():
   if time.monotonic_ns()-start>timeout*10**9:raise TimeoutError('COMMAND_TIMEOUT')
   for key,_ in sel.select(.05):
    b=os.read(key.fd,65536)
    if not b:sel.unregister(key.fileobj);continue
    dest=out if key.data=='out' else err;dest.extend(b)
    if len(out)+len(err)>limit:raise Refused('COMMAND_LIMIT')
  rc=p.wait(timeout=1)
  if rc or err:raise Refused('COMMAND_FAILED_'+str(rc))
  return bytes(out)
 finally:
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
  sel.close();p.stdout.close();p.stderr.close()

class Unix(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect('/run/docker.sock')

def docker(path):
 if path not in ('/version','/containers/'+CONTAINER+'/json'):raise Refused('DOCKER_PATH')
 c=Unix('localhost',timeout=15)
 try:
  c.request('GET',path);r=c.getresponse();b=r.read(2_000_001)
  if r.status!=200 or len(b)>2_000_000:raise Refused('DOCKER_RESPONSE')
  return json.loads(b)
 finally:c.close()

def identity(c):
 if c['Id']!=CONTAINER or c['Image']!=IMAGE or not c['State']['Running']:raise Refused('CONTAINER_DRIFT')
 nets=c['NetworkSettings']['Networks']
 if set(nets)!={'tausendunde1nz_net','telegram_chatbot_default'}:raise Refused('NETWORK_DRIFT')
 return {'id':c['Id'],'image':c['Image'],'pid':c['State']['Pid'],'started':c['State']['StartedAt'],
  'name':c['Name'].lstrip('/'),'service':c['Config']['Labels'].get('com.docker.compose.service'),
  'bindings':c['HostConfig']['PortBindings'],
  'networks':{n:{k:e.get(k) for k in ('NetworkID','IPAddress','GlobalIPv6Address','MacAddress','Aliases','Gateway','IPv6Gateway')} for n,e in nets.items()}}

def terms(ident):
 t={('Hostport','8081'),('Containerport','8080'),('Servicename',ident['service']),('Containername',ident['name'])}
 for e in ident['networks'].values():
  t.update(('IP',e[k]) for k in ('IPAddress','GlobalIPv6Address') if e.get(k))
  if e.get('MacAddress'):t.add(('MAC',e['MacAddress']))
  t.update(('Alias',x) for x in e.get('Aliases') or [])
 if any(not isinstance(v,str) or not v for _,v in t):raise Refused('NETWORK_TERM')
 return sorted(t)

def hits(value,network_terms):
 return [{'type':kind,'reference':v} for kind,v in network_terms if re.search(
   r'(?<![\w.:])'+re.escape(v)+r'(?![\w.:])' if kind=='MAC' else
   r'(?<![\w.])'+re.escape(v)+r'(?![\w.])',str(value))]

def wal_checksum(raw,endian,seed=(0,0)):
 if len(raw)%8:raise Refused('WAL_CHECKSUM_ALIGNMENT')
 a,b=seed
 for x,y in struct.iter_unpack(endian+'II',raw):a=(a+x+b)&0xffffffff;b=(b+y+a)&0xffffffff
 return a,b

def materialize(db,wal):
 """Validate complete SQLite WAL, apply only the last committed prefix in RAM."""
 if len(db)<100 or db[:16]!=b'SQLite format 3\x00':raise Refused('SQLITE_HEADER')
 page=int.from_bytes(db[16:18],'big');page=65536 if page==1 else page
 if page<512 or page>65536 or page&(page-1) or len(db)%page:raise Refused('SQLITE_PAGE_SIZE')
 if not wal:
  if db[18:20]==b'\x02\x02':
   # A WAL-mode database with no WAL has no pending committed WAL frames.
   pass
  result=bytearray(db)
 else:
  if len(wal)<32:raise Refused('WAL_HEADER')
  magic,version,wpage,seq,salt1,salt2,c1,c2=struct.unpack('>8I',wal[:32])
  if magic not in (0x377f0682,0x377f0683) or version!=3007000 or wpage!=page:raise Refused('WAL_FORMAT')
  endian='<' if magic==0x377f0682 else '>'
  checksum=wal_checksum(wal[:24],endian)
  if checksum!=(c1,c2):raise Refused('WAL_HEADER_CHECKSUM')
  if (len(wal)-32)%(24+page):raise Refused('WAL_PARTIAL_FRAME')
  frames=[];commit=-1;size=0
  for at in range(32,len(wal),24+page):
   h=wal[at:at+24];payload=wal[at+24:at+24+page]
   pg,n,s1,s2,f1,f2=struct.unpack('>6I',h)
   if not pg or pg*page>LIMIT or n*page>LIMIT or (s1,s2)!=(salt1,salt2):raise Refused('WAL_FRAME')
   checksum=wal_checksum(h[:8]+payload,endian,checksum)
   if checksum!=(f1,f2):raise Refused('WAL_FRAME_CHECKSUM')
   frames.append((pg,payload))
   if n:commit=len(frames)-1;size=n
  result=bytearray(db)
  if commit>=0:
   result=result[:size*page];result.extend(b'\x00'*(size*page-len(result)))
   for pg,payload in frames[:commit+1]:
    if pg<=size:result[(pg-1)*page:pg*page]=payload
 result[18:20]=b'\x01\x01' # memory-only standalone SQLite snapshot, no disk journal
 return bytes(result)

def scan_database(snapshot,network_terms):
 c=sqlite3.connect(':memory:')
 try:
  c.deserialize(snapshot);c.execute('PRAGMA query_only=ON');c.execute('PRAGMA trusted_schema=OFF');c.enable_load_extension(False)
  schema=c.execute("SELECT type,sql FROM sqlite_master WHERE name='workflow_entity'").fetchall()
  if len(schema)!=1 or schema[0][0]!='table' or not re.match(r'^\s*CREATE\s+TABLE\b',schema[0][1],re.I):raise Refused('N8N_SCHEMA')
  result=[];indirections=[];count=0
  for ident,active,nodes in c.execute('SELECT id,active,nodes FROM workflow_entity'):
   count+=1
   if count>10000:raise Refused('N8N_COUNT')
   ident=str(ident)
   if not re.fullmatch('[A-Za-z0-9_-]{1,64}',ident):raise Refused('N8N_RECORD_ID')
   parsed=json.loads(nodes)
   if not isinstance(parsed,list):raise Refused('N8N_NODES_TYPE')
   for nodeidx,node in enumerate(parsed):
    # Never emit arbitrary keys, node names, surrounding values or credentials.
    if isinstance(node,dict) and node.get('credentials'):
     indirections.append({'record_id':ident,'node_index':nodeidx,'active':bool(active),'type':'CREDENTIAL_REFERENCE_NOT_DECRYPTED'})
    stack=[node.get('parameters',{})] if isinstance(node,dict) else []
    scalar=0
    while stack:
     x=stack.pop()
     if isinstance(x,dict):stack.extend(x.values())
     elif isinstance(x,list):stack.extend(x)
     else:
      scalar+=1
      if scalar>100000:raise Refused('N8N_PARAMETERS_BOUND')
      if isinstance(x,str) and any(v in x for v in ('{{','$env','$json','$node')):
       indirections.append({'record_id':ident,'node_index':nodeidx,'active':bool(active),'type':'DYNAMIC_EXPRESSION_NOT_EXECUTED'})
      found=hits(x,network_terms)
      if found:result.append({'record_id':ident,'node_index':nodeidx,'parameter_scalar_ordinal':scalar,
        'active':bool(active),'actually_consumed':'NOT_PROVEN_BY_CONFIGURATION','references':found})
  return {'workflow_count':count,'matches':result,'unresolved_indirections':indirections}
 finally:c.close()

def n8n(ident):
 for attempt in range(3):
  try:
   db,a=read(DB,owner=1000)
   try:wal,b=read(str(DB)+'-wal',owner=1000)
   except FileNotFoundError:wal,b=b'',None
   db2,a2=read(DB,owner=1000)
   try:wal2,b2=read(str(DB)+'-wal',owner=1000)
   except FileNotFoundError:wal2,b2=b'',None
   if a!=a2 or b!=b2:continue
   data=scan_database(materialize(db,wal),terms(ident))
   data['source']={'database_sha256':a['sha256'],'wal_sha256':None if b is None else b['sha256'],'attempt':attempt+1}
   data['protected_configs']=[]
   for path in CONFIGS:
    raw,meta=read(path,2*1024*1024,owner=0)
    records=[{'line':i,'references':hits(line,terms(ident))} for i,line in enumerate(raw.decode().splitlines(),1) if hits(line,terms(ident))]
    data['protected_configs'].append({'path':path,'sha256':meta['sha256'],'matches':records})
   return data
  except Refused as e:
   if str(e)=='READ_DRIFT':continue
   raise
 raise Refused('N8N_CONCURRENT_WRITE_NO_SNAPSHOT')

IDENT=re.compile(r'^[A-Za-z0-9_.:-]{1,100}$')
def name(x):
 if not isinstance(x,str) or not IDENT.fullmatch(x):raise Refused('RULE_IDENTIFIER')
 return x

def redact_expr(x):
 if isinstance(x,list):return [redact_expr(v) for v in x]
 if isinstance(x,dict):return {k:redact_expr(v) for k,v in x.items() if k not in ('counter','packets','bytes','expires','used','comment')}
 if isinstance(x,(int,bool)) or x is None:return x
 if isinstance(x,str):
  if re.fullmatch(r'[0-9]{1,5}',x) and int(x)<=65535:return x
  if re.fullmatch(r'[0-9.]+:[0-9]{1,5}',x):
   address,port=x.rsplit(':',1)
   try:ipaddress.IPv4Address(address)
   except ValueError:raise Refused('NAT_ADDRESS')
   if int(port)>65535:raise Refused('NAT_PORT')
   return {'address':address,'port':int(port)}
  safe={'ip','ip6','tcp','udp','icmp','icmpv6','ether','th','dport','sport','saddr','daddr','iifname','oifname','iif','oif','nfproto','l4proto','ipv4','ipv6','accept','drop','return','established','related','new','invalid','==','!=','in','&','|','ct','state','mark','dnat','snat'}
  try:ipaddress.ip_network(x,strict=False);return x
  except ValueError:pass
  if x in safe or re.fullmatch(r'(?:br-[0-9a-f]{12}|docker[0-9]+|eth[0-9]+|ens[0-9]+|tailscale[0-9]+|lo|DOCKER(?:-[A-Z0-9-]+)?)',x):return x
  return {'redacted_string_sha256':sha(x.encode())}
 raise Refused('RULE_EXPR_TYPE')

def nft_evidence(raw,ident):
 data=json.loads(raw);chains={};rules=[]
 for item in data['nftables']:
  if 'chain' in item:
   c=item['chain'];key=(c['family'],c['table'],c['name']);chains[key]=c
  if 'rule' in item:rules.append(item['rule'])
 needles=[e['IPAddress'] for e in ident['networks'].values() if e.get('IPAddress')]+[e['GlobalIPv6Address'] for e in ident['networks'].values() if e.get('GlobalIPv6Address')]
 selected=set()
 for r in rules:
  expr=json.dumps(r.get('expr',[]));key=(r['family'],r['table'],r['chain'])
  if re.search(r'\b8081\b',expr) or any(ip in expr for ip in needles):selected.add(key)
 def targets(r):
  result=[]
  for e in r.get('expr',[]):
   for k in ('jump','goto'):
    if k in e:result.append((r['family'],r['table'],e[k]['target']))
  return result
 changed=True
 while changed:
  changed=False
  for r in rules:
   key=(r['family'],r['table'],r['chain'])
   if any(t in selected for t in targets(r)) and key not in selected:selected.add(key);changed=True
 out=[]
 for key in sorted(selected):
  c=chains.get(key)
  if c is None:raise Refused('NFT_CHAIN_MISSING')
  rows=[]
  for index,r in enumerate(x for x in rules if (x['family'],x['table'],x['chain'])==key):
   expr=json.dumps(r.get('expr',[]));relevant=bool(re.search(r'\b8081\b',expr)) or any(ip in expr for ip in needles) or any(t in selected for t in targets(r))
   if not relevant:
    rows.append({'ordinal':index,'nonmatching_rule_structure_sha256':sha(encode(redact_expr(r.get('expr',[]))))});continue
   rows.append({'ordinal':index,'handle':r.get('handle'),'expr':redact_expr(r.get('expr',[])),
    'comment_sha256':sha(r['comment'].encode()) if 'comment' in r else None,
    'jumps':[{'family':name(t[0]),'table':name(t[1]),'chain':name(t[2])} for t in targets(r)]})
  out.append({'family':name(key[0]),'table':name(key[1]),'chain':name(key[2]),
    'hook':c.get('hook'),'priority':c.get('prio'),'policy':c.get('policy'),'type':c.get('type'),'rules':rows,
    'ownership':'DOCKER_CHAIN_CONSISTENT' if key[2].startswith('DOCKER') else 'UFW_CHAIN_CONSISTENT' if key[2].lower().startswith('ufw') else 'BASE_OR_OTHER_NOT_ATTRIBUTED'})
 return {'chains':out,'structure_sha256':sha(encode(out)),'raw_sha256':sha(raw),'counters':'OMITTED'}

def iptables_evidence(raw,ident):
 import shlex
 table=None;chains={};rules=[];policies={}
 ips=[e['IPAddress'] for e in ident['networks'].values() if e.get('IPAddress')]
 for line in raw.decode().splitlines():
  if line.startswith('*'):table=line[1:]
  elif line.startswith(':'):
   t=line.split();chains[(table,t[0][1:])]=[];policies[(table,t[0][1:])]=t[1]
  elif line.startswith('-A '):
   t=shlex.split(line);key=(table,t[1]);chains.setdefault(key,[]).append(t);rules.append((key,t))
 selected=set()
 for key,t in rules:
  if '8081' in t or any(any(x==ip or x.startswith(ip+':') or x==ip+'/32' for ip in ips) for x in t):selected.add(key)
 def jump(t):return t[t.index('-j')+1] if '-j' in t else t[t.index('-g')+1] if '-g' in t else None
 changed=True
 while changed:
  changed=False
  for key,t in rules:
   if (key[0],jump(t)) in selected and key not in selected:selected.add(key);changed=True
 rows=[]
 for key in sorted(selected):
  entries=[]
  for i,t in enumerate(chains[key]):
   relevant='8081' in t or any(any(x==ip or x.startswith(ip+':') or x==ip+'/32' for ip in ips) for x in t) or (key[0],jump(t)) in selected
   if not relevant:
    entries.append({'ordinal':i,'nonmatching_rule':True});continue
   fields={};flags=[];at=2
   while at<len(t):
    k=t[at]
    if k=='--comment':fields['comment_sha256']=sha(t[at+1].encode());at+=2;continue
    if k in ('-p','-s','-d','-i','-o','-m','--dport','--sport','--dports','--sports','--to-destination','--to-source','--dst-type','--src-type','--ctstate','--match-set','--mark','--tcp-flags'):
     v=t[at+1];fields.setdefault(k,[]).append(redact_expr(v));at+=2;continue
    if k in ('-j','-g'):fields[k]=name(t[at+1]);at+=2;continue
    if k=='-c':at+=3;continue
    flags.append(redact_expr(k));at+=1
   entries.append({'ordinal':i,'fields':fields,'flags':flags})
  rows.append({'table':name(key[0]),'chain':name(key[1]),'policy':policies.get(key),'hook':key[1] if key[1] in ('PREROUTING','INPUT','FORWARD','OUTPUT','POSTROUTING') else None,'rules':entries})
 return {'chains':rows,'structure_sha256':sha(encode(rows)),'raw_sha256':sha(raw),'counters':'OMITTED'}

def nat(ident):
 versions={k:command([p,'--version']).decode().strip() for k,p in [('iptables','/usr/sbin/iptables'),('ip6tables','/usr/sbin/ip6tables')]}
 for v in versions.values():
  if not re.fullmatch(r'[A-Za-z0-9 .()_+-]{1,150}',v):raise Refused('BACKEND_VERSION')
 result={'versions':versions,'ipv4':iptables_evidence(command(['/usr/sbin/iptables-save']),ident),
         'ipv6':iptables_evidence(command(['/usr/sbin/ip6tables-save']),ident),
         'nft':nft_evidence(command(['/usr/sbin/nft','-j','list','ruleset']),ident),
         'publishing':ident['bindings'],'docker_version':{k:v for k,v in docker('/version').items() if k in ('Version','ApiVersion','GitCommit')}}
 try:raw,_=read('/etc/docker/daemon.json',1024*1024,owner=0);conf=json.loads(raw)
 except FileNotFoundError:conf={}
 result['daemon_firewall_settings']={k:conf[k] for k in ('firewall-backend','iptables','ip6tables') if k in conf}
 for k,v in result['daemon_firewall_settings'].items():
  if k=='firewall-backend' and v not in ('iptables','nftables'):raise Refused('BACKEND_UNKNOWN')
  if k!='firewall-backend' and type(v) is not bool:raise Refused('BACKEND_TYPE')
 pidraw=command(['/usr/bin/systemctl','show','-p','MainPID','--value','--','docker.service']).decode().strip()
 if not pidraw.isdigit() or int(pidraw)<=1:raise Refused('DOCKER_PID')
 stat_before=Path('/proc/'+pidraw+'/stat').read_bytes().rsplit(b')',1)[1].split()[19]
 argv=Path('/proc/'+pidraw+'/cmdline').read_bytes().split(b'\0');settings={}
 for i,arg in enumerate(argv):
  for flag in (b'--firewall-backend',b'--iptables',b'--ip6tables'):
   if arg==flag or arg.startswith(flag+b'='):
    value=arg.split(b'=',1)[1] if b'=' in arg else argv[i+1]
    if value not in (b'iptables',b'nftables',b'true',b'false'):raise Refused('DOCKER_CLI_FIREWALL_SETTING')
    settings[flag.decode()]=value.decode()
 if Path('/proc/'+pidraw+'/stat').read_bytes().rsplit(b')',1)[1].split()[19]!=stat_before:raise Refused('DOCKER_PID_RACE')
 result['daemon_cli_firewall_settings']=settings
 result['ownership_limit']='Chain, Docker port publishing and backend establish structural attribution; no historic actor attribution or production recreation is performed.'
 result['ipv6_note']='An absent kernel IPv6 DNAT rule does not exclude a docker-proxy IPv6 listener; inspect publishing and listener evidence together.'
 # Read host sockets without contacting a public endpoint; fixed port only.
 raw=command(['/usr/bin/ss','-H','-lntp','sport = :8081'])
 result['listeners_8081']=[]
 for line in raw.decode().splitlines():
  t=line.split()
  if len(t)<5:raise Refused('SS_PARSE')
  process='docker-proxy' if '"docker-proxy"' in line else 'OTHER_PROCESS_REDACTED'
  result['listeners_8081'].append({'local_address':t[3],'process':process})
 return result

def apparmor():
 raw=base64.b64decode(APPARMOR_SOURCE_B64,validate=True)
 if sha(raw)!=APPARMOR_SHA256:raise Refused('APPARMOR_SOURCE_HASH')
 m=types.ModuleType('v12_bound_apparmor');exec(compile(raw,'<bound-apparmor>','exec'),m.__dict__)
 data=m.collect()
 def strip(x):
  if isinstance(x,dict):return {k:strip(v) for k,v in x.items() if k not in ('text','includes')}
  if isinstance(x,list):return [strip(v) for v in x]
  return x
 return strip(data)

def atomic(dirfd,name,data,mode=0o600):
 if not re.fullmatch('[a-z0-9-]+[.]json',name):raise Refused('ARTIFACT_NAME')
 tmp='.'+name+'-'+os.urandom(8).hex();fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=dirfd)
 try:
  with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(encode(data)+b'\n');f.flush();os.fsync(f.fileno())
  os.link(tmp,name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False);os.unlink(tmp,dir_fd=dirfd);os.fsync(dirfd)
 finally:
  try:os.unlink(tmp,dir_fd=dirfd)
  except FileNotFoundError:pass

def run_sections(functions,writer,clock=time.monotonic_ns):
 records=[];artifacts={};interrupted=False
 try:
  for section,fn in functions:
   start=clock()
   try:
    data=fn();status='OK';error=None;error_code=None;timeout=False
   except Exception as e:
    data=None;status='ERROR';error=type(e).__name__;timeout=isinstance(e,TimeoutError)
    error_code=str(e) if type(e).__name__=='Refused' and re.fullmatch(r'[A-Za-z0-9_]{1,80}',str(e)) else None
   record={'section':section,'start_ns':start,'end_ns':clock(),'status':status,'error_class':error,'error_code':error_code,'timeout':timeout,'data':data}
   writer(section+'.json',record);artifacts[section+'.json']=sha(encode(record)+b'\n');records.append({'section':section,'status':status})
 except BaseException as e:interrupted=True;records.append({'section':'interruption','status':'ERROR','error_class':type(e).__name__})
 finally:
  manifest={'version':'12.0','status':'INCOMPLETE' if interrupted or any(x['status']!='OK' for x in records) else 'COMPLETE','sections':records,'sha256':artifacts}
  writer('manifest.json',manifest)
 return manifest

def main():
 if os.geteuid()!=0 or not __debug__ or len(sys.argv)!=1:raise Refused('ROOT_REQUIRED')
 root=Path(__file__).parent.parent
 if not re.fullmatch(r'/var/lib/tu1nz-evidence-v12-[a-z0-9_]+',str(root)):raise Refused('ROOT_PATH')
 for p in [root,root/'staging',Path(__file__)]:
  s=p.lstat()
  if s.st_uid!=0 or s.st_mode&0o022 or stat.S_ISLNK(s.st_mode):raise Refused('ROOT_TRUST')
  if any('posix_acl' in x for x in os.listxattr(p,follow_symlinks=False)):raise Refused('ROOT_ACL')
 if stat.S_IMODE((root/'staging').stat().st_mode)!=0o700 or stat.S_IMODE(Path(__file__).stat().st_mode)!=0o600:raise Refused('ROOT_EXACT_MODE')
 for n,mode in [('private',0o700),('public',0o755)]:
  os.mkdir(root/n,mode);os.chmod(root/n,mode)
 private=os.open(root/'private',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 public=os.open(root/'public',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def writer(n,d):atomic(private,n,d);atomic(public,n,d,0o644)
 def interrupted(*_):raise KeyboardInterrupt()
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 try:
  baseline=identity(docker('/containers/'+CONTAINER+'/json'))
  def continuity():
   current=identity(docker('/containers/'+CONTAINER+'/json'))
   if current!=baseline:raise Refused('CONTAINER_CHANGED_DURING_COLLECTION')
   return {'unchanged':True}
  bootstrap_hashes={n:sha((root/n).read_bytes()) for n in ('bootstrap-start.json','bootstrap-complete.json')}
  completed=json.loads((root/'bootstrap-complete.json').read_bytes())
  if completed.get('status')!='COPY_VERIFIED_BEFORE_EXECUTION' or completed.get('sha256')!=sha(Path(__file__).read_bytes()):raise Refused('BOOTSTRAP_EVIDENCE')
  metadata={'bootstrap_evidence_sha256':bootstrap_hashes,'version':'12.0','python_version':list(sys.version_info[:3]),'isolated':bool(sys.flags.isolated),'bytecode_disabled':bool(sys.dont_write_bytecode),'collector_sha256':sha(Path(__file__).read_bytes()),'apparmor_sha256':APPARMOR_SHA256,'effective_uid':os.geteuid(),'private_mode':'0600','public_mode':'0644','database_disk_copy':False}
  if not metadata['isolated'] or not metadata['bytecode_disabled']:raise Refused('PYTHON_FLAGS')
  manifest=run_sections([('run',lambda:metadata),('identity',lambda:baseline),('n8n',lambda:n8n(baseline)),('nat',lambda:nat(baseline)),('apparmor',apparmor),('continuity',continuity)],writer)
  print(json.dumps({'status':manifest['status'],'public_path':str(root/'public'),'manifest_sha256':sha(encode(manifest)+b'\n')}))
  return 0 if manifest['status']=='COMPLETE' else 2
 except BaseException as e:
  if not (root/'private/manifest.json').exists():writer('manifest.json',{'version':'12.0','status':'INCOMPLETE','error_class':type(e).__name__})
  return 2
 finally:os.close(private);os.close(public)

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:
  print(json.dumps({'status':'INCOMPLETE','error_class':type(e).__name__}));raise SystemExit(2)
