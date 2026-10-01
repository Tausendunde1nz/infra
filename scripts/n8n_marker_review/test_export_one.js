'use strict';
const assert=require('assert'),vm=require('vm'),crypto=require('crypto');
function load(source){let sandbox={module:{exports:{}},require:()=>{throw Error('UNEXPECTED_REQUIRE')}};sandbox.require.main={};vm.runInNewContext(source,sandbox);return sandbox.module.exports.exportOne;}
async function test(source){
 const run=load(source);let count=0;
 async function one(change,expected){
  let calls=[],phase=0;const cfg={};change(cfg);
  const st={uid:1000,nlink:1,size:100,ino:1,dev:1,mtimeMs:1,ctimeMs:1,isFile:()=>true};
  const fs={constants:{O_RDONLY:0,O_NOFOLLOW:1},lstatSync:p=>{if(cfg.wal)return {isFile:()=>true,isSymbolicLink:()=>false,size:9};const e=Error();e.code='ENOENT';throw e;},openSync:(p,f)=>{assert.equal(p,'/home/node/.n8n/database.sqlite');if(cfg.symlink)throw Error('LINK');return 1;},fstatSync:()=>({...st,uid:cfg.owner?0:1000}),readFileSync:()=>Buffer.from(cfg.drift&&phase++?'changed':'fixture'),closeSync:()=>{},writeFileSync:()=>{throw Error('WRITE');}};
  class Database {constructor(uri,flags,cb){assert.equal(uri,'file:/home/node/.n8n/database.sqlite?mode=ro&immutable=1');assert.equal(flags,65|262144);queueMicrotask(()=>cb(cfg.open?Error():null));}all(sql,args,cb){calls.push(sql);if(sql.startsWith('PRAGMA'))return cb(null,[]);if(sql.includes('sqlite_master'))return cb(null,[{type:cfg.view?'view':'table',sql:'CREATE TABLE workflow_entity (id)'}]);assert.equal(sql,'SELECT * FROM workflow_entity WHERE id = ?');assert.equal(args[0],'ptNQ8rpGMyk1zGx3');cb(null,cfg.missing?[]:[{id:'ptNQ8rpGMyk1zGx3',active:cfg.inactive?0:1,nodes:'[]'}]);}close(cb){cb(null);}}
  const sqlite={Database,OPEN_READONLY:1,OPEN_URI:64,OPEN_PRIVATECACHE:262144};
  if(expected)await assert.rejects(()=>run(fs,crypto,sqlite,cfg.uid?0:1000));else{const x=await run(fs,crypto,sqlite,1000);assert.equal(x.workflow.id,'ptNQ8rpGMyk1zGx3');assert.equal(calls.length,4);}
  count++;
 }
 await one(c=>{},false);
 for(const k of ['wal','symlink','owner','drift','open','view','missing','inactive','uid'])await one(c=>c[k]=true,true);
 console.log('PASS',count,'offline export cases; no production DB used');
}
module.exports={test};
