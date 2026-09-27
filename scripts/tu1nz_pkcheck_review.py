"""Interpret verified noninteractive pkcheck evidence, never execute actions."""
AUTH_REQUIRED_STDERR_SHA='3f53664d5fb5e9c4b1ef73f8783306bbfbd74052fb1f5614e066454f38632a13'
def classify(record):
 args=record.get('argv',[])
 if len(args)!=5 or args[0]!='/usr/bin/pkcheck' or args[1]!='--action-id' or args[3]!='--process':return 'ERROR'
 if not args[2].startswith('org.freedesktop.packagekit.'):return 'ERROR'
 if record.get('timeout') or record.get('overflow') or record.get('exception'):return 'ERROR'
 code=record.get('rc')
 if code==0:return 'AUTHORIZED'
 if code==1:return 'NOT_AUTHORIZED'
 if code==2 and record.get('stdout_raw',{}).get('bytes')==0 and record.get('stderr_raw',{}).get('bytes')==60 and record.get('stderr_raw',{}).get('sha256')==AUTH_REQUIRED_STDERR_SHA:
  return 'NOT_AUTHORIZED_AUTH_REQUIRED'
 return 'ERROR'
