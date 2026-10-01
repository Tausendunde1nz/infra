"""Pure, hash-bound transformation. Never reads or writes the live secret."""
import hashlib,re
SOURCE_SHA='467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264'
class Refused(ValueError):pass

def transform(original):
 if hashlib.sha256(original).hexdigest()!=SOURCE_SHA:raise Refused('SOURCE_DRIFT')
 return _transform(original)

def _transform(original):
 text=original.decode()
 if len(re.findall(r'^BOT_TOKEN=.*$',text,re.M))!=1 or len(re.findall(r'\bcurl\b',text))!=1:raise Refused('UNEXPECTED_SHAPE')
 assignment='BOT_TOKEN="$(cat -- "${CREDENTIALS_DIRECTORY:?}/trendwatch-token")"\n[[ "$BOT_TOKEN" =~ ^[0-9]{6,16}:[A-Za-z0-9_-]{25,}$ ]] || exit 77'
 text=re.sub(r'^BOT_TOKEN=.*$',lambda m:assignment,text,flags=re.M)
 url=r'"https://api\.telegram\.org/bot\$\{?BOT_TOKEN\}?/sendMessage"'
 if len(re.findall(url,text))!=1:raise Refused('URL_SHAPE')
 text=re.sub(url,'--config -',text)
 prefix=r'''printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$BOT_TOKEN" | curl'''
 text=re.sub(r'\bcurl\b',lambda m:prefix,text,count=1)
 for a,b in [('sudo mkdir -p /opt/trendwatch','mkdir -p /opt/trendwatch'),('sudo tee /opt/trendwatch/today_title.txt','tee /opt/trendwatch/today_title.txt')]:
  if text.count(a)!=1:raise Refused('SUDO_SHAPE')
  text=text.replace(a,b)
 if 'sudo ' in text:raise Refused('UNREVIEWED_SUDO')
 # Disable inherited tracing before any credential is opened.
 lines=text.splitlines();lines.insert(1,'set +x');text='\n'.join(lines)+'\n'
 if re.search(r'[0-9]{6,16}:[A-Za-z0-9_-]{25,}',text):raise Refused('LITERAL_CREDENTIAL_REMAINS')
 return text.encode()

def credential_dropin():
 return '[Service]\nLoadCredential=trendwatch-token:/etc/tu1nz/credentials/trendwatch-token\nUnsetEnvironment=BOT_TOKEN BASH_ENV ENV SHELLOPTS BASHOPTS\n'
