// Local trusted-coordinator experiment. One immutable admission per height.
// No network consensus orchestration, real money or resistance to full rollback.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createRoundCirculationLab} from './pay-circulation-lab.mjs';
const check=v=>{if(!v)throw Error('Round chain refused');};
const MAX=131072;
function pack(v){const s=JSON.stringify(v);check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);return s;}
function unpack(s){check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);const v=JSON.parse(s);check(pack(v)===s);return v;}
export function openRoundChain({directory,config,createNew=false,clock=Date.now}){
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const lab=createRoundCirculationLab(structuredClone(config)),base=lab.snapshot([]),path=join(directory,'chain.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){const st=lstatSync(p);check(realpathSync(p)===p&&st.uid===process.getuid()&&(st.mode&0o077)===0&&(dir?st.isDirectory():st.isFile()&&st.nlink===1));}
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),network TEXT NOT NULL,count INTEGER NOT NULL,root TEXT NOT NULL); CREATE TABLE rounds(height INTEGER PRIMARY KEY,scope TEXT NOT NULL UNIQUE,admission TEXT NOT NULL,certificate TEXT);');
   db.prepare('INSERT INTO meta VALUES(1,?,0,?)').run(base.network,base.root);db.exec('COMMIT');
  }
  function tx(write,fn){
   check(!closed&&!halted);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');let out;
   try{out=fn();}catch(e){try{db.exec('ROLLBACK')}catch{halted=true;}throw e;}
   try{db.exec('COMMIT')}catch(e){halted=true;try{db.exec('ROLLBACK')}catch{}throw e;}return out;
  }
  function read(){
   const m=db.prepare('SELECT * FROM meta').all(),rows=db.prepare('SELECT * FROM rounds ORDER BY height LIMIT 33').all();
   check(m.length===1&&m[0].network===base.network&&Number.isInteger(m[0].count)&&m[0].count>=0&&m[0].count<=32&&rows.length<=32);
   const records=[],receipts=[];let pending=null;
   for(const [i,row] of rows.entries()){
    check(row.height===i+1&&!pending);
    const admission=unpack(row.admission),info=lab.admit(records,admission);check(info.scope===row.scope);
    if(row.certificate===null){pending={admission,info};continue;}
    const record={admission,certificate:unpack(row.certificate)};
    receipts.push(lab.receipt(records,record));records.push(record);
   }
   const snapshot=lab.snapshot(records);
   check(records.length===m[0].count&&snapshot.root===m[0].root);
   return {records,receipts,pending,snapshot};
  }
  tx(false,read);
  return Object.freeze({
   snapshot:()=>tx(false,()=>{const s=read();return Object.freeze({...s.snapshot,pendingScope:s.pending?.info.scope??null,pendingHeight:s.pending?s.snapshot.sequence+1:null,realPaymentAuthorized:false});}),
   transcript:lab.transcript,
   prepare:params=>tx(false,()=>{const s=read();check(!s.pending&&s.snapshot.sequence<32);return lab.prepare(s.records,{...params,now:clock()});}),
   admission:()=>tx(false,()=>structuredClone(read().pending)),
   receipts:()=>tx(false,()=>read().receipts),
   admit(proposals){
    const input=structuredClone(proposals);
    return tx(true,()=>{
     const s=read();check(s.snapshot.sequence<32);
     if(s.pending){check(pack(input)===pack(s.pending.admission.proposals));return structuredClone(s.pending.info);}
     const admission={proposals:input,admissionTime:clock()},info=lab.admit(s.records,admission);
     db.prepare('INSERT INTO rounds VALUES(?,?,?,NULL)').run(s.snapshot.sequence+1,info.scope,pack(admission));
     return structuredClone(info);
    });
   },
   commit(certificate){
    const raw=pack(structuredClone(certificate));
    return tx(true,()=>{
     const s=read(),cert=unpack(raw);
     const index=s.receipts.findIndex(r=>r.scope===cert?.prepared?.scope);
     if(index>=0){
      const record={admission:s.records[index].admission,certificate:cert},r=lab.receipt(s.records.slice(0,index),record);
      check(r.root===s.receipts[index].root&&r.nonce===s.receipts[index].nonce);return s.receipts[index];
     }
     check(s.pending);
     const record={admission:s.pending.admission,certificate:cert},r=lab.receipt(s.records,record);
     check(r.scope===s.pending.info.scope&&r.sequence===s.snapshot.sequence+1);
     check(db.prepare('UPDATE rounds SET certificate=? WHERE height=? AND scope=? AND certificate IS NULL').run(raw,r.sequence,r.scope).changes===1);
     check(db.prepare('UPDATE meta SET count=?,root=? WHERE id=1 AND count=? AND root=?').run(r.sequence,r.root,s.snapshot.sequence,s.snapshot.root).changes===1);
     check(read().snapshot.root===r.root);return r;
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
