// Isolated, single-wallet, fictional PSP/merchant/central-ledger experiment.
// It never contacts any financial provider or assigns redeemable balances.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {previewPayDictionary} from './pay-iso20022-preview.mjs';
import {verifyHistoricalPayProof,summarizePayProofs} from './pay-lab-checkpoint.mjs';
const check=v=>{if(!v)throw Error('Synthetic settlement refused');};
const initial=10000;
const hex=/^[a-f0-9]{64}$/;
export function openPaySettlementLab({directory,createNew=false,scope,trustedAuthorities,clock=Date.now}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 const pins=Object.freeze({...scope}),trusted=structuredClone(trustedAuthorities);
 summarizePayProofs([],pins);
 check(Array.isArray(trusted)&&trusted.length===4&&trusted.every(t=>hex.test(t.pin)&&hex.test(t.pqPin))&&new Set(trusted.map(t=>t.pin)).size===4&&new Set(trusted.map(t=>t.pqPin)).size===4);
 const binding=JSON.stringify([pins.signingPin,pins.pqPin,trusted.map(t=>[t.pin,t.pqPin]).sort((a,b)=>a[0].localeCompare(b[0]))]);
 const path=join(directory,'settlement.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){
  const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE scope (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL); CREATE TABLE transfers (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, reference TEXT NOT NULL UNIQUE, payee TEXT NOT NULL, cents INTEGER NOT NULL CHECK(cents BETWEEN 1 AND 10000));');
   db.prepare('INSERT INTO scope VALUES(1,?)').run(binding);db.exec('COMMIT');
  }
  function read(){
   check(!closed);const meta=db.prepare('SELECT * FROM scope').all();check(meta.length===1&&meta[0].binding===binding);
   const rows=db.prepare('SELECT * FROM transfers ORDER BY nonce LIMIT 101').all();check(rows.length<=100);
   let merchant=0,person=0;
   for(const r of rows){check(hex.test(r.nonce)&&hex.test(r.digest)&&/^LAB-[a-f0-9]{30}$/.test(r.reference)&&Number.isSafeInteger(r.cents)&&r.cents>=1&&r.cents<=initial&&['demo-shop','demo-person'].includes(r.payee));if(r.payee==='demo-shop')merchant+=r.cents;else person+=r.cents;}
   check(merchant+person<=initial);
   return {rows,balance:{wallet:initial-merchant-person,merchant,person,total:initial,simulationOnly:true,redeemable:false}};
  }
  function tx(write,fn){
   check(!closed);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
   try{const r=fn();db.exec('COMMIT');return r;}catch(e){try{db.exec('ROLLBACK')}catch{}throw e;}
  }
  tx(false,read);
  function receipt(r){return Object.freeze({nonce:r.nonce,reference:r.reference,cents:r.cents,payee:r.payee,status:'LAB_SETTLED',simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false});}
  return Object.freeze({
   balances:()=>tx(false,()=>Object.freeze(read().balance)),
   lookup(nonce){check(typeof nonce==='string'&&hex.test(nonce));return tx(false,()=>{const r=read().rows.find(v=>v.nonce===nonce);return r?receipt(r):null;});},
   settle({localProofs,nonce,request,attestations}){
    // Fresh signed reconciliation from independently configured keys, not a
    // caller-provided approved flag or dictionary preview.
    check(request.signingPin===pins.signingPin&&request.pqPin===pins.pqPin);
    const view=previewPayDictionary({localProofs,nonce,request,trustedAuthorities:trusted,attestations,now:clock()});
    const p=localProofs.find(x=>x.intent.Nonce===nonce),proof=verifyHistoricalPayProof(p,pins);
    const reference=view.paymentIdentification.endToEndIdentification;
    return tx(true,()=>{
     const {rows,balance}=read();
     const existing=rows.find(r=>r.nonce===nonce);
     if(existing){check(existing.digest===proof.digest&&existing.reference===reference&&existing.cents===proof.cents&&existing.payee===p.intent.Payee);return receipt(existing);}
     check(rows.length<100&&balance.wallet>=proof.cents);
     // All entries must still be present in the newly attested wallet history.
     const byNonce=new Map(localProofs.map(x=>[x.intent.Nonce,verifyHistoricalPayProof(x,pins)]));
     check(rows.every(r=>byNonce.get(r.nonce)?.digest===r.digest));
     db.prepare('INSERT INTO transfers VALUES(?,?,?,?,?)').run(nonce,proof.digest,reference,p.intent.Payee,proof.cents);
     const stored=read().rows.find(r=>r.nonce===nonce);check(stored);return receipt(stored);
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
