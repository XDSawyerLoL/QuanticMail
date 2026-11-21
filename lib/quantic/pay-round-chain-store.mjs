// Local trusted-coordinator experiment. One immutable admission per height.
// No network consensus orchestration, real money or resistance to full rollback.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createRoundCirculationLab} from './pay-circulation-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Round chain refused');};
export function openRoundChain({directory,config,createNew=false,clock=Date.now,authorityPin=null}){
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const lab=createRoundCirculationLab(structuredClone(config)),base=lab.snapshot([]),path=join(directory,'chain.sqlite');
 const MAX=lab.committeeMode?1024*1024:131072;
 function pack(v){const s=JSON.stringify(v);check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);return s;}
 function unpack(s){check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);const v=JSON.parse(s);check(pack(v)===s);return v;}
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){const st=lstatSync(p);check(realpathSync(p)===p&&st.uid===process.getuid()&&(st.mode&0o077)===0&&(dir?st.isDirectory():st.isFile()&&st.nlink===1));}
 const db=new DatabaseSync(path);let closed=false,halted=false;
 check(authorityPin===null||(typeof authorityPin==='string'&&/^[a-f0-9]{64}$/.test(authorityPin)&&config.witnesses.some(w=>w.pin===authorityPin)));
 const binding=pack(['quantic-round-chain-owner/v1',base.network,authorityPin]);
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),network TEXT NOT NULL,count INTEGER NOT NULL,root TEXT NOT NULL); CREATE TABLE rounds(height INTEGER PRIMARY KEY,scope TEXT NOT NULL UNIQUE,admission TEXT NOT NULL,certificate TEXT);');
   if(lab.gated)db.exec('CREATE TABLE admission_locks(height INTEGER PRIMARY KEY,scope TEXT NOT NULL,draft TEXT NOT NULL,vote TEXT NOT NULL);');
   if(lab.committeeMode)db.exec('CREATE TABLE admission_rounds(height INTEGER PRIMARY KEY,scope TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,0,?)').run(binding,base.root);db.exec('COMMIT');
  }
  function tx(write,fn){
   check(!closed&&!halted);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');let out;
   try{out=fn();}catch(e){try{db.exec('ROLLBACK')}catch{halted=true;}throw e;}
   try{db.exec('COMMIT')}catch(e){halted=true;try{db.exec('ROLLBACK')}catch{}throw e;}return out;
  }
  function read(){
   const m=db.prepare('SELECT * FROM meta').all(),rows=db.prepare('SELECT * FROM rounds ORDER BY height LIMIT 33').all();
   check(m.length===1&&m[0].network===binding&&Number.isInteger(m[0].count)&&m[0].count>=0&&m[0].count<=32&&rows.length<=32);
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
   if(lab.gated){
    const locks=db.prepare('SELECT * FROM admission_locks ORDER BY height LIMIT 33').all();
    check(locks.length<=32&&(authorityPin!==null||locks.length===0));
    for(const l of locks){
     check(Number.isInteger(l.height)&&l.height>=1&&l.height<=Math.min(32,snapshot.sequence+1));
     const prefix=records.slice(0,l.height-1),draft=unpack(l.draft),v=unpack(l.vote);
     check(lab.draft(prefix,draft).scope===l.scope&&lab.inspectAdmissionVote(prefix,draft,v)===authorityPin);
    }
   }
   if(lab.committeeMode){
    const reservations=db.prepare('SELECT * FROM admission_rounds ORDER BY height LIMIT 33').all();
    check(reservations.length<=32&&(authorityPin!==null||reservations.length===0));
    for(const entry of reservations){
     check(Number.isInteger(entry.height)&&entry.height>=1&&entry.height<=Math.min(32,snapshot.sequence+1));
     check(createPayRoundLab(lab.admissionRoundConfig(records.slice(0,entry.height-1))).scope===entry.scope);
    }
   }
   return {records,receipts,pending,snapshot};
  }
  tx(false,read);
  return Object.freeze({
   snapshot:()=>tx(false,()=>{const s=read();return Object.freeze({...s.snapshot,pendingScope:s.pending?.info.scope??null,pendingHeight:s.pending?s.snapshot.sequence+1:null,realPaymentAuthorized:false});}),
   transcript:lab.transcript,
   reserveAdmissionRound(scope,{reserve=false}={}){
    return tx(reserve,()=>{
     const s=read();check(lab.committeeMode&&authorityPin!==null);
     if(s.snapshot.sequence===32){check(!reserve);return null;}
     if(reserve)check(!s.pending);
     const rc=lab.admissionRoundConfig(s.records),expected=createPayRoundLab(rc).scope;
     const old=db.prepare('SELECT scope FROM admission_rounds WHERE height=?').get(rc.height);
     if(old)check(old.scope===expected);
     if(!reserve&&!old)return null;
     if(reserve)check(scope===expected);
     if(reserve&&!old)db.prepare('INSERT INTO admission_rounds VALUES(?,?)').run(rc.height,expected);
     return {height:rc.height,scope:expected,records:structuredClone(s.records),created:reserve&&!old};
    });
   },
   draft(input){return tx(false,()=>{const s=read();check(lab.gated&&!s.pending);return lab.draft(s.records,structuredClone(input));});},
   admissionReport(){
    return tx(false,()=>{
     const s=read();check(lab.gated&&!lab.roundGated&&authorityPin!==null);
     const height=s.snapshot.sequence+1,l=db.prepare('SELECT * FROM admission_locks WHERE height=?').get(height);
     return l?{height,scope:l.scope,draft:unpack(l.draft),vote:unpack(l.vote)}:null;
    });
   },
   recoverAdmission(reports){
    return tx(false,()=>{
     const s=read();check(lab.gated&&!lab.roundGated&&!s.pending&&Array.isArray(reports)&&reports.length<=4);
     const seen=new Set(),groups=new Map();
     for(const r of structuredClone(reports)){
      if(r===null)continue;
      const d=lab.draft(s.records,r.draft),p=lab.inspectAdmissionVote(s.records,r.draft,r.vote);
      check(d.height===r.height&&d.scope===r.scope&&!seen.has(p));seen.add(p);
      if(!groups.has(d.scope))groups.set(d.scope,{draft:r.draft,votes:[]});
      groups.get(d.scope).votes.push(r.vote);
     }
     const winner=[...groups.values()].find(g=>g.votes.length>=3);
     const sizes=[...groups.values()].map(g=>g.votes.length).sort((a,b)=>b-a);
     if(!winner)return {state:'blocked-no-admission-quorum',groups:sizes,admission:null,automaticUnlock:false,simulationOnly:true};
     const admission={...winner.draft,endorsements:winner.votes};
     lab.admit(s.records,admission);
     const now=clock(),fresh=Number.isSafeInteger(now)&&now>=admission.admissionTime&&now-admission.admissionTime<=15000&&admission.proposals.every(p=>now<p.intent.expires);
     return {state:fresh?'recovered-admission-quorum':'expired-admission-quorum',groups:sizes,admission:fresh?admission:null,automaticUnlock:false,simulationOnly:true};
    });
   },
   voteAdmission(input,credentials){
    const draft=structuredClone(input);
    return tx(true,()=>{
     const s=read();check(lab.gated&&!lab.roundGated&&authorityPin!==null&&credentials.authorityPin===authorityPin&&!s.pending);
     const d=lab.draft(s.records,draft),old=db.prepare('SELECT * FROM admission_locks WHERE height=?').get(d.height);
     if(old){check(old.scope===d.scope);return unpack(old.vote);}
     const now=clock();check(Number.isSafeInteger(now)&&now>=draft.admissionTime&&now-draft.admissionTime<=15000&&draft.proposals.every(p=>now<p.intent.expires));
     const vote=lab.signAdmission(s.records,draft,credentials);
     db.prepare('INSERT INTO admission_locks VALUES(?,?,?,?)').run(d.height,d.scope,pack(draft),pack(vote));
     return vote;
    });
   },
   prepare:params=>tx(false,()=>{const s=read();check(!s.pending&&s.snapshot.sequence<32);return lab.prepare(s.records,{...params,now:clock()});}),
   admission:()=>tx(false,()=>structuredClone(read().pending)),
   receipts:()=>tx(false,()=>read().receipts),
   record(height){return tx(false,()=>{const s=read();check(Number.isInteger(height)&&height>=1&&height<=s.records.length);return structuredClone(s.records[height-1]);});},
   // For preconfigured replica operators, persist the identical admission,
   // rather than deriving a fresh scope from the receiver's local clock.
   admitExact(input){
    const admission=structuredClone(input);
    return tx(true,()=>{
     const s=read();check((authorityPin!==null||lab.gated)&&s.snapshot.sequence<32);
     if(s.pending){check(pack(admission)===pack(s.pending.admission));return {created:false,info:structuredClone(s.pending.info)};}
     const now=clock();check(Number.isSafeInteger(now)&&Number.isSafeInteger(admission?.admissionTime)&&now>=admission.admissionTime&&now-admission.admissionTime<=15000);
     check(Array.isArray(admission.proposals)&&admission.proposals.every(p=>now<p.intent.expires));
     const info=lab.admit(s.records,admission);
     db.prepare('INSERT INTO rounds VALUES(?,?,?,NULL)').run(s.snapshot.sequence+1,info.scope,pack(admission));
     return {created:true,info:structuredClone(info)};
    });
   },
   // Catch up a replica that never admitted/voted at this height. A pending
   // admission is not overwritten; it must complete through its own journal.
   syncCertified(input){
    const record=structuredClone(input);
    return tx(true,()=>{
     const s=read();check(authorityPin!==null&&!s.pending&&s.snapshot.sequence<32);
     const r=lab.receipt(s.records,record);
     check(r.sequence===s.snapshot.sequence+1);
     db.prepare('INSERT INTO rounds VALUES(?,?,?,?)').run(r.sequence,r.scope,pack(record.admission),pack(record.certificate));
     check(db.prepare('UPDATE meta SET count=?,root=? WHERE id=1 AND count=? AND root=?').run(r.sequence,r.root,s.snapshot.sequence,s.snapshot.root).changes===1);
     check(read().snapshot.root===r.root);return r;
    });
   },
   admit(proposals){
    const input=structuredClone(proposals);
    return tx(true,()=>{
     const s=read();check(!lab.gated&&s.snapshot.sequence<32);
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
