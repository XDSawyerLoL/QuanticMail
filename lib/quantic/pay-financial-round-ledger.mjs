// One fixed-height fictional ledger, separate from old single-phase history.
// Trusted provisioning, fixed candidate set, local disk and process owner.
// No real money, no live PSP, no multi-height or cross-installation finality.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
import {openFinancialRound} from './pay-financial-round.mjs';
const check=v=>{if(!v)throw Error('Financial round ledger refused');};
const sha=s=>createHash('sha256').update(s).digest('hex');
const MAX=131072;
function pack(v){const s=JSON.stringify(v);check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);return s;}
function unpack(s){check(typeof s==='string'&&Buffer.byteLength(s)<=MAX);const v=JSON.parse(s);check(pack(v)===s);return v;}
export function openFinancialRoundLedger({directory,createNew=false,config,records,proposals,admissionTime}){
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const round=openFinancialRound({config,records,proposals,admissionTime}),base=round.base();
 const binding=pack(['quantic-financial-round-ledger/v1',round.scope,base.network,base.sequence,base.root,base.totalCents]);
 const path=join(directory,'financial-round.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){
  const st=lstatSync(p);check(realpathSync(p)===p&&st.uid===process.getuid()&&(st.mode&0o077)===0&&(dir?st.isDirectory():st.isFile()&&st.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, committed INTEGER NOT NULL CHECK(committed IN(0,1)), root TEXT NOT NULL); CREATE TABLE decision(id INTEGER PRIMARY KEY CHECK(id=1), certificate TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, nonce TEXT NOT NULL, root TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,0,?)').run(binding,base.root);db.exec('COMMIT');
  }
  function tx(write,fn){
   check(!closed&&!halted);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');let result;
   try{result=fn();}catch(e){try{db.exec('ROLLBACK')}catch{halted=true;}throw e;}
   try{db.exec('COMMIT');}catch(e){halted=true;try{db.exec('ROLLBACK')}catch{}throw e;}
   return result;
  }
  function receipt(p){
   const t=p.transaction;
   return Object.freeze({status:'LAB_ROUND_COMMITTED',scope:p.scope,sequence:p.sequence,round:p.round,
    reference:'LAB-'+t.value.slice(0,30),nonce:t.nonce,payer:t.payer,payee:t.payee,cents:t.cents,currency:'EUR',
    previousRoot:p.previousRoot,root:p.projectedRoot,simulationOnly:true,ledgerCommitted:true,realPaymentAuthorized:false,settlementVerified:false});
  }
  function state(){
   const meta=db.prepare('SELECT * FROM meta').all(),rows=db.prepare('SELECT * FROM decision LIMIT 2').all();
   check(meta.length===1&&meta[0].id===1&&meta[0].binding===binding&&[0,1].includes(meta[0].committed)&&rows.length===meta[0].committed);
   if(!rows.length){check(meta[0].root===base.root);return {projection:null,receipt:null};}
   const row=rows[0],cert=unpack(row.certificate);check(row.id===1&&sha(row.certificate)===row.digest);
   const p=round.project(cert);
   check(p.scope===round.scope&&p.sequence===base.sequence+1&&p.previousRoot===base.root&&p.totalCents===base.totalCents&&p.transaction.value===row.value&&p.transaction.nonce===row.nonce&&p.projectedRoot===row.root&&row.root===meta[0].root);
   return {projection:p,receipt:receipt(p)};
  }
  function snapshot(){
   const s=state(),p=s.projection;
   return Object.freeze({scope:round.scope,network:base.network,sequence:p?.sequence??base.sequence,root:p?.projectedRoot??base.root,balances:Object.freeze({...p?.balances??base.balances}),totalCents:base.totalCents,committedCount:p?1:0,simulationOnly:true,redeemable:false,realPaymentAuthorized:false,settlementVerified:false});
  }
  tx(false,state);
  return Object.freeze({
   snapshot:()=>tx(false,snapshot),
   receipt:()=>tx(false,()=>state().receipt),
   commit(certificate){
    const raw=pack(structuredClone(certificate));
    return tx(true,()=>{
     const p=round.project(unpack(raw)),s=state();
     if(s.projection){
      // Subsequent equivalent certificates are harmless; retain the first
      // exact verified certificate and its receipt. No second state change.
      check(s.projection.transaction.value===p.transaction.value&&s.projection.projectedRoot===p.projectedRoot);
      return s.receipt;
     }
     check(p.sequence===base.sequence+1&&p.previousRoot===base.root&&p.totalCents===base.totalCents);
     db.prepare('INSERT INTO decision VALUES(1,?,?,?,?,?)').run(raw,sha(raw),p.transaction.value,p.transaction.nonce,p.projectedRoot);
     check(db.prepare('UPDATE meta SET committed=1,root=? WHERE id=1 AND committed=0 AND root=?').run(p.projectedRoot,base.root).changes===1);
     const stored=state();check(stored.receipt?.root===p.projectedRoot);return stored.receipt;
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
