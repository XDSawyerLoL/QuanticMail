// Persistent single-authority vote lock, synthetic Linux laboratory only.
// No timeout-based unlock, view-change protocol or protection from disk rollback.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {createCirculationLab} from './pay-circulation-lab.mjs';
const check=v=>{if(!v)throw Error('Circulation witness store refused');};
const hash=b=>createHash('sha256').update(b).digest('hex');
const pin=k=>hash(createPublicKey(k).export({type:'spki',format:'der'}));
function pack(v,max){const s=JSON.stringify(v);check(typeof s==='string'&&Buffer.byteLength(s)<=max);return s;}
function unpack(s,max){check(typeof s==='string'&&Buffer.byteLength(s)<=max);return JSON.parse(s);}
export function openCirculationWitness({directory,createNew=false,config,authorityPin,classicalPrivateKey,pqPrivateKey,clock=Date.now}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const lab=createCirculationLab(config),genesis=lab.snapshot([]).network;
 const own=config.witnesses.find(w=>w.pin===authorityPin);
 check(own&&classicalPrivateKey?.type==='private'&&pqPrivateKey?.type==='private'&&pin(classicalPrivateKey)===own.pin&&pin(pqPrivateKey)===own.pqPin);
 const binding=JSON.stringify(['circulation-store/v1',genesis,own.pin,own.pqPin]);
 const path=join(directory,'circulation.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){
  const st=lstatSync(p);check(realpathSync(p)===p&&st.uid===process.getuid()&&(st.mode&0o077)===0&&(dir?st.isDirectory():st.isFile()&&st.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, sequence INTEGER NOT NULL, root TEXT NOT NULL); CREATE TABLE committed (seq INTEGER PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE votes (seq INTEGER PRIMARY KEY, body TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,0,?)').run(binding,genesis);db.exec('COMMIT');
  }
  function state(){
   check(!closed);const meta=db.prepare('SELECT * FROM meta').all();check(meta.length===1&&meta[0].binding===binding);
   const rows=db.prepare('SELECT * FROM committed ORDER BY seq LIMIT 257').all();
   check(rows.length<=256&&rows.length===meta[0].sequence);
   const records=rows.map((r,i)=>{check(r.seq===i+1);return unpack(r.body,32768);});
   const snapshot=lab.snapshot(records);check(snapshot.root===meta[0].root);
   const votes=db.prepare('SELECT * FROM votes ORDER BY seq LIMIT 257').all();check(votes.length<=256);
   let pending=null;
   for(const r of votes){
    check(r.seq>=1&&r.seq<=records.length+1);
    const v=unpack(r.body,16384);
    check(v.vote.pin===own.pin&&v.vote.pqPin===own.pqPin&&v.proof.intent.sequence===r.seq);
    const info=lab.inspectVote(records.slice(0,r.seq-1),v.proof,v.decidedAt,v.vote);
    if(r.seq<=records.length){
     const record=records[r.seq-1];
     check(hash(lab.transcript(record.proof.intent))===info.digest&&record.decidedAt===v.decidedAt);
    }else{check(!pending);pending=v;}
   }
   return {records,snapshot,pending};
  }
  function tx(write,fn){
   check(!closed);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
   try{const result=fn();db.exec('COMMIT');return result;}catch(e){try{db.exec('ROLLBACK')}catch{}throw e;}
  }
  tx(false,state);
  return Object.freeze({
   status:()=>tx(false,()=>{const s=state();return Object.freeze({...s.snapshot,pendingSequence:s.pending?.proof.intent.sequence??null});}),
   vote({proof,decidedAt}){
    proof=structuredClone(proof);
    return tx(true,()=>{
     const s=state(),now=clock();
     check(Number.isSafeInteger(now)&&now>=decidedAt&&now-decidedAt<=15000&&now<proof.intent.expires);
     if(s.pending){
      const p=s.pending;
      check(p.decidedAt===decidedAt&&hash(lab.transcript(p.proof.intent))===hash(lab.transcript(proof.intent)));
      // The supplied proof must itself be valid, even for exact retries.
      lab.inspectVote(s.records,proof,decidedAt,p.vote);
      return Object.freeze(p.vote);
     }
     const v=lab.attest({retainedRecords:s.records,proof,decidedAt,authorityPin:own.pin,classicalPrivateKey,pqPrivateKey,now});
     db.prepare('INSERT INTO votes VALUES(?,?)').run(proof.intent.sequence,pack({proof,decidedAt,vote:v},16384));
     return v; // tx commits before releasing the signature to the caller.
    });
   },
   commit(record){
    record=structuredClone(record);
    return tx(true,()=>{
     const s=state(),seq=record.proof.intent.sequence;
     if(seq<=s.records.length){
      check(pack(record,32768)===pack(s.records[seq-1],32768));return s.snapshot;
     }
     check(seq===s.records.length+1);
     if(s.pending)check(s.pending.decidedAt===record.decidedAt&&hash(lab.transcript(s.pending.proof.intent))===hash(lab.transcript(record.proof.intent)));
     // Historical quorum verification allows delayed application of a valid
     // certificate. It does not establish external real-time finality.
     const next=lab.snapshot([...s.records,record]);
     db.prepare('INSERT INTO committed VALUES(?,?)').run(seq,pack(record,32768));
     check(db.prepare('UPDATE meta SET sequence=?,root=? WHERE id=1 AND sequence=? AND root=?').run(seq,next.root,s.snapshot.sequence,s.snapshot.root).changes===1);
     return next;
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
