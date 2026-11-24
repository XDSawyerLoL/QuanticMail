// Separate multi-wallet fictional settlement laboratory. Existing signed demo
// beneficiaries keep their exact meaning; no dynamic account routing or PSP.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {previewPayDictionary} from './pay-iso20022-preview.mjs';
import {verifyHistoricalPayProof,summarizePayProofs} from './pay-lab-checkpoint.mjs';
const check=x=>{if(!x)throw Error('Multi-wallet laboratory refused');};
const hex=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const ids=['demo-alice','demo-bob','demo-person'];
const accounts=[...ids,'demo-shop'];
function trustedKey(encoded,pin,type,length){
 check(typeof encoded==='string'&&typeof pin==='string'&&hex.test(pin));
 const raw=Buffer.from(encoded,'base64url');check(raw.length===length&&raw.toString('base64url')===encoded&&sha(raw)===pin);
 const k=createPublicKey({key:raw,type:'spki',format:'der'});check(k.asymmetricKeyType===type&&k.export({type:'spki',format:'der'}).equals(raw));
}
export function openMultiwalletLab({directory,createNew=false,wallets,clock=Date.now}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 check(Array.isArray(wallets)&&wallets.length===3&&new Set(wallets.map(w=>w.id)).size===3);
 const policies=new Map(),walletPins=new Set();
 for(const w of structuredClone(wallets)){
  check(ids.includes(w.id));summarizePayProofs([],w.scope);
  for(const p of [w.scope.signingPin,w.scope.pqPin]){check(!walletPins.has(p));walletPins.add(p);}
  check(Array.isArray(w.trustedAuthorities)&&w.trustedAuthorities.length===4);
  const classical=new Set(),pq=new Set();
  for(const a of w.trustedAuthorities){
   trustedKey(a.publicKey,a.pin,'ed25519',44);trustedKey(a.pqPublicKey,a.pqPin,'ml-dsa-65',1974);
   check(!classical.has(a.pin)&&!pq.has(a.pqPin));classical.add(a.pin);pq.add(a.pqPin);
  }
  policies.set(w.id,w);
 }
 const binding=JSON.stringify(['quantic-multiwallet-lab/v1',...ids.map(id=>{const w=policies.get(id);return [id,w.scope.signingPin,w.scope.pqPin,w.trustedAuthorities.map(a=>[a.pin,a.pqPin]).sort((a,b)=>a[0]<b[0]?-1:1)];})]);
 const path=join(directory,'multiwallet.sqlite');
 if(createNew===true){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}else check(createNew===false);
 for(const [p,dir] of [[directory,true],[path,false]]){
  const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE lab_meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL); CREATE TABLE transfers (seq INTEGER PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, digest TEXT NOT NULL UNIQUE, reference TEXT NOT NULL UNIQUE, payer TEXT NOT NULL, payee TEXT NOT NULL, cents INTEGER NOT NULL CHECK(cents BETWEEN 1 AND 10000), proof TEXT NOT NULL);');
   db.prepare('INSERT INTO lab_meta VALUES(1,?)').run(binding);db.exec('COMMIT');
  }
  const read=()=>{
   check(!closed);const meta=db.prepare('SELECT * FROM lab_meta').all();check(meta.length===1&&meta[0].binding===binding);
   const rows=db.prepare('SELECT * FROM transfers ORDER BY seq LIMIT 301').all();check(rows.length<=300);
   const balances=Object.fromEntries(accounts.map(id=>[id,id==='demo-shop'?0:10000]));
   const sent=Object.fromEntries(ids.map(id=>[id,0]));
   for(const [i,r] of rows.entries()){
    check(r.seq===i+1&&policies.has(r.payer)&&['demo-shop','demo-person'].includes(r.payee)&&r.payer!==r.payee&&Number.isSafeInteger(r.cents)&&r.cents>=1&&r.cents<=10000&&typeof r.proof==='string'&&Buffer.byteLength(r.proof)<=32768);
    const p=JSON.parse(r.proof),v=verifyHistoricalPayProof(p,policies.get(r.payer).scope);
    check(v.nonce===r.nonce&&v.digest===r.digest&&v.cents===r.cents&&p.intent.Payee===r.payee&&r.reference==='LAB-'+sha(Buffer.from(JSON.stringify(['quantic-pay-preview/v1',v.digest]))).slice(0,30));
    check(balances[r.payer]>=r.cents&&sent[r.payer]+r.cents<=10000);
    balances[r.payer]-=r.cents;balances[r.payee]+=r.cents;sent[r.payer]+=r.cents;
   }
   check(Object.values(balances).reduce((a,b)=>a+b,0)===30000);
   return {rows,balances,sent};
  };
  function tx(write,fn){check(!closed);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');try{const r=fn();db.exec('COMMIT');return r;}catch(e){try{db.exec('ROLLBACK')}catch{}throw e;}}
  tx(false,read);
  const receipt=r=>Object.freeze({nonce:r.nonce,reference:r.reference,payer:r.payer,payee:r.payee,cents:r.cents,status:'LAB_SETTLED',simulationOnly:true,realPaymentAuthorized:false,settlementVerified:false});
  return Object.freeze({
   snapshot:()=>tx(false,()=>{const s=read();return Object.freeze({balances:Object.freeze(s.balances),outgoingCents:Object.freeze(s.sent),totalCents:30000,transferCount:s.rows.length,simulationOnly:true,redeemable:false});}),
   lookup(nonce){check(typeof nonce==='string'&&hex.test(nonce));return tx(false,()=>{const r=read().rows.find(x=>x.nonce===nonce);return r?receipt(r):null;});},
   settle({payer,localProofs,nonce,request,attestations}){
    const w=policies.get(payer);check(w&&request.signingPin===w.scope.signingPin&&request.pqPin===w.scope.pqPin);
    const view=previewPayDictionary({localProofs,nonce,request,trustedAuthorities:w.trustedAuthorities,attestations,now:clock()});
    const p=localProofs.find(x=>x.intent.Nonce===nonce),v=verifyHistoricalPayProof(p,w.scope);
    check(payer!==p.intent.Payee&&localProofs.length<=100);
    const ref=view.paymentIdentification.endToEndIdentification;
    const raw=JSON.stringify(p);check(Buffer.byteLength(raw)<=32768);
    return tx(true,()=>{
     const state=read(),own=state.rows.filter(r=>r.payer===payer);
     const known=new Map(localProofs.map(p=>[p.intent.Nonce,verifyHistoricalPayProof(p,w.scope)]));
     check(own.every(r=>known.get(r.nonce)?.digest===r.digest));
     const existing=state.rows.find(r=>r.nonce===nonce);
     if(existing){check(existing.payer===payer&&existing.digest===v.digest&&existing.reference===ref);return receipt(existing);}
     check(own.length<100&&state.rows.length<300&&state.balances[payer]>=v.cents&&state.sent[payer]+v.cents<=10000);
     db.prepare('INSERT INTO transfers VALUES(?,?,?,?,?,?,?,?)').run(state.rows.length+1,nonce,v.digest,ref,payer,p.intent.Payee,v.cents,raw);
     const stored=read().rows.at(-1);return receipt(stored);
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
