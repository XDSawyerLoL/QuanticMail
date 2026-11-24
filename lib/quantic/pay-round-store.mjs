// Linux-only synthetic round authority. Separate DB per authority/height.
// No production funds, OS-level rollback resistance or independent network.
// Replays bounded signed journal under an exclusive transaction; release only
// after durable commit. Same-user directory and SQLite implementation trusted.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Persistent round laboratory refused');};
const sha=s=>createHash('sha256').update(s).digest('hex');
const exact=(o,keys)=>o&&typeof o==='object'&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const ops=['prepare','commit','changeView','learn'];
const LIMIT=256,LEGACY_MAX=131072,COMMITTEE_MAX=5*1024*1024,JOURNAL_MAX=64*1024*1024;
export function openPersistentPayRound({directory,createNew=false,config,authorityPin,classicalPrivateKey,pqPrivateKey}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const lab=createPayRoundLab(config),credentials={authorityPin,classicalPrivateKey,pqPrivateKey};
 lab.openAuthority(credentials);
 const MAX=config.committeeMode===true?COMMITTEE_MAX:LEGACY_MAX;
 function pack(o){const s=JSON.stringify(o);check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);return s;}
 function unpack(s){check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);const o=JSON.parse(s);check(pack(o)===s);return o;}
 function storedBytes(){const n=db.prepare('SELECT coalesce(sum(length(CAST(body AS BLOB))),0) AS n FROM events').get().n;check(Number.isSafeInteger(n)&&n>=0&&n<=JOURNAL_MAX);return n;}
 const binding=pack(['quantic-pay-round-store/v1',lab.scope,authorityPin]),genesis=sha(binding);
 const path=join(directory,'round.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){
  const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, count INTEGER NOT NULL, root TEXT NOT NULL); CREATE TABLE events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, root TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,0,?)').run(binding,genesis);db.exec('COMMIT');
  }
  function tx(write,fn){
   check(!closed&&!halted);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
   let result;
   try{result=fn();}catch(e){try{db.exec('ROLLBACK')}catch{halted=true;}throw e;}
   try{db.exec('COMMIT');}catch(e){halted=true;try{db.exec('ROLLBACK')}catch{}throw e;}
   return result;
  }
  function describe(action,input,out){return pack(lab.inspectOutput(action,input,out,authorityPin));}
  function replay(){
   const meta=db.prepare('SELECT * FROM meta').all();check(meta.length===1&&meta[0].binding===binding&&Number.isInteger(meta[0].count)&&meta[0].count>=0&&meta[0].count<=LIMIT);
   storedBytes();
   const rows=db.prepare('SELECT * FROM events ORDER BY seq LIMIT 257').all();check(rows.length===meta[0].count);
   const node=lab.openAuthority(credentials),outputs=new Map();let root=genesis;
   for(const [i,row] of rows.entries()){
    check(row.seq===i+1);
    const e=unpack(row.body);
    check(exact(e,['action','input','output'])&&ops.includes(e.action));
    root=sha(pack([root,row.seq,sha(row.body)]));check(root===row.root);
    // Replay transitions using the pinned keys. Any newly generated
    // signatures here are discarded; only the original retained signed
    // output can ever be returned as a retry.
    const actual=node[e.action](e.input),semantic=describe(e.action,e.input,actual);
    check(semantic===describe(e.action,e.input,e.output)&&!outputs.has(semantic));
    outputs.set(semantic,e.output);
   }
   check(root===meta[0].root);
   return {node,outputs,count:rows.length,root};
  }
  tx(false,replay);
  function act(action,input){
   input=structuredClone(input);pack(input);
   return tx(true,()=>{
    const s=replay();
    const generated=s.node[action](input),semantic=describe(action,input,generated);
    if(s.outputs.has(semantic))return structuredClone(s.outputs.get(semantic));
    check(s.count<LIMIT);
    const seq=s.count+1,body=pack({action,input,output:generated}),root=sha(pack([s.root,seq,sha(body)]));
    check(storedBytes()+Buffer.byteLength(body)<=JOURNAL_MAX);
   db.prepare('INSERT INTO events VALUES(?,?,?)').run(seq,body,root);
    check(db.prepare('UPDATE meta SET count=?,root=? WHERE id=1 AND count=? AND root=?').run(seq,root,s.count,s.root).changes===1);
    return structuredClone(generated);
   });
  }
  return Object.freeze({
   status:()=>tx(false,()=>{const s=replay();return Object.freeze({...s.node.status(),ephemeral:false,journalCount:s.count,journalRoot:s.root,simulationOnly:true});}),
   prepare:input=>act('prepare',input),
   commit:input=>act('commit',input),
   changeView:input=>act('changeView',input),
   learn:input=>act('learn',input),
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
