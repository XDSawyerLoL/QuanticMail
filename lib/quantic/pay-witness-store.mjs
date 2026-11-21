// Linux-only, private local persistent witness laboratory. No public service,
// real money or authority independence implied. Same OS user is trusted.
// The signing key is supplied separately; it is never stored in this database.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {isAbsolute,dirname,join} from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {attestPayCheckpoint,summarizePayProofs,verifyHistoricalPayProof} from './pay-lab-checkpoint.mjs';
const check=v=>{if(!v)throw Error('Pay witness laboratory refused');};
const hex=/^[a-f0-9]{64}$/;
const publicPin=k=>createHash('sha256').update(createPublicKey(k).export({type:'spki',format:'der'})).digest('hex');
function privateObject(path,dir){
 const s=lstatSync(path);check(realpathSync(path)===path&&s.uid===process.getuid()&&(s.mode&0o077)===0);
 check(dir?s.isDirectory():s.isFile()&&s.nlink===1);
}
export function openPayWitnessStore({directory,createNew=false,scope,authorityPrivateKey,expectedAuthorityPin,clock=Date.now}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 check(authorityPrivateKey?.type==='private'&&authorityPrivateKey.asymmetricKeyType==='ed25519'&&hex.test(expectedAuthorityPin)&&publicPin(authorityPrivateKey)===expectedAuthorityPin);
 const pins=Object.freeze({signingPin:scope.signingPin,pqPin:scope.pqPin});
 summarizePayProofs([],pins);
 const path=join(directory,'witness.sqlite');
 if(createNew===true){
  mkdirSync(directory,{mode:0o700});
  const fd=openSync(path,'wx',0o600);closeSync(fd);
 }else{check(createNew===false);}
 privateObject(directory,true);privateObject(path,false);
 const db=new DatabaseSync(path);
 let closed=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), signing TEXT NOT NULL, pq TEXT NOT NULL, authority TEXT NOT NULL, count INTEGER NOT NULL, root TEXT NOT NULL); CREATE TABLE proofs (seq INTEGER PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, body TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,?,?,?,?)').run(pins.signingPin,pins.pqPin,expectedAuthorityPin,0,summarizePayProofs([],pins).root);
   db.exec('COMMIT');
  }
  function read(){
   check(!closed);
   const m=db.prepare('SELECT * FROM meta').all();check(m.length===1&&m[0].id===1&&m[0].signing===pins.signingPin&&m[0].pq===pins.pqPin&&m[0].authority===expectedAuthorityPin);
   check(Number.isSafeInteger(m[0].count)&&m[0].count>=0&&m[0].count<=100);
   const rows=db.prepare('SELECT seq, nonce, body FROM proofs ORDER BY seq LIMIT 101').all();
   check(rows.length===m[0].count);
   const proofs=rows.map((r,i)=>{
    check(r.seq===i+1&&typeof r.body==='string'&&Buffer.byteLength(r.body)<=32768);
    const p=JSON.parse(r.body);check(verifyHistoricalPayProof(p,pins).nonce===r.nonce);return p;
   });
   const summary=summarizePayProofs(proofs,pins);check(summary.root===m[0].root&&summary.count===m[0].count);
   return {proofs,summary};
  }
  function transaction(write,fn){
   check(!closed);db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
   try{const result=fn();db.exec('COMMIT');return result;}catch(e){try{db.exec('ROLLBACK')}catch{/* Fail closed. */}throw e;}
  }
  transaction(false,read);
  return Object.freeze({
   summary:()=>transaction(false,()=>read().summary),
   vote(request){return transaction(false,()=>{
    check(request.signingPin===pins.signingPin&&request.pqPin===pins.pqPin);
    return attestPayCheckpoint({retainedProofs:read().proofs,request,authorityPrivateKey,now:clock()});
   })},
   append(proof,prior){return transaction(true,()=>{
    const {proofs,summary}=read();check(prior?.count===summary.count&&prior.root===summary.root&&proofs.length<100);
    const p=structuredClone(proof),v=verifyHistoricalPayProof(p,pins),now=clock();
    check(Number.isSafeInteger(now)&&now>=p.intent.Issued&&now<p.intent.Expires&&!proofs.some(x=>x.intent.Nonce===v.nonce));
    check(proofs.reduce((n,x)=>n+x.intent.Cents,0)+v.cents<=10000);
    const body=JSON.stringify(p);check(Buffer.byteLength(body)<=32768);
    const next=summarizePayProofs([...proofs,p],pins);
    db.prepare('INSERT INTO proofs VALUES(?,?,?)').run(next.count,v.nonce,body);
    const updated=db.prepare('UPDATE meta SET count=?,root=? WHERE id=1 AND count=? AND root=?').run(next.count,next.root,summary.count,summary.root);
    check(updated.changes===1);
    return next;
   })},
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
