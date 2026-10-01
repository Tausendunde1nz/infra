'use strict';
// One workflow, no n8n bootstrap, migrations, execution, or production writes.
const DB='/home/node/.n8n/database.sqlite';
const ID='ptNQ8rpGMyk1zGx3';
async function exportOne(fs,crypto,sqlite,uid) {
 if(uid!==1000) throw Error('SERVICE_UID');
 function stamp(){
  for(const suffix of ['-wal','-journal']) {
   try {const s=fs.lstatSync(DB+suffix);if(!s.isFile()||s.isSymbolicLink()||s.size)throw Error('JOURNAL_PRESENT');}
   catch(e){if(e.code!=='ENOENT')throw e;}
  }
  const fd=fs.openSync(DB,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
   const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==1000||s.nlink!==1||s.size>134217728)throw Error('DB_IDENTITY');
   const raw=fs.readFileSync(fd);const z=fs.fstatSync(fd);
   if(s.ino!==z.ino||s.size!==z.size||s.mtimeMs!==z.mtimeMs||s.ctimeMs!==z.ctimeMs)throw Error('DB_READ_DRIFT');
   return {dev:s.dev,ino:s.ino,size:s.size,mtime:s.mtimeMs,ctime:s.ctimeMs,sha256:crypto.createHash('sha256').update(raw).digest('hex')};
  } finally {fs.closeSync(fd);}
 }
 const before=stamp();let db;
 try {
  db=await new Promise((resolve,reject)=>{const d=new sqlite.Database('file:'+DB+'?mode=ro&immutable=1',sqlite.OPEN_READONLY|sqlite.OPEN_URI|sqlite.OPEN_PRIVATECACHE,e=>e?reject(e):resolve(d));});
  const all=(sql,args=[])=>new Promise((resolve,reject)=>db.all(sql,args,(e,r)=>e?reject(e):resolve(r)));
  await all('PRAGMA query_only=ON');await all('PRAGMA trusted_schema=OFF');
  const schema=await all("SELECT type,sql FROM sqlite_master WHERE name='workflow_entity'");
  if(schema.length!==1||schema[0].type!=='table'||!/^CREATE TABLE\b/i.test(schema[0].sql))throw Error('SCHEMA');
  const rows=await all('SELECT * FROM workflow_entity WHERE id = ?',[ID]);
  if(rows.length!==1||rows[0].id!==ID||rows[0].active!==1)throw Error('WORKFLOW_IDENTITY');
  const after=stamp();if(JSON.stringify(before)!==JSON.stringify(after))throw Error('DB_DRIFT');
  return {format:'single-readonly-workflow-row-v1',id:ID,database:before,workflow:rows[0]};
 } finally {if(db)await new Promise((resolve,reject)=>db.close(e=>e?reject(e):resolve()));}
}
module.exports={exportOne};
if(require.main===module){
 const fs=require('fs'),crypto=require('crypto');
 const sqlite=require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3/lib/sqlite3.js');
 exportOne(fs,crypto,sqlite,process.getuid()).then(x=>process.stdout.write(JSON.stringify(x)+'\n')).catch(()=>{process.stderr.write('EXPORT_REFUSED\n');process.exitCode=2;});
}
