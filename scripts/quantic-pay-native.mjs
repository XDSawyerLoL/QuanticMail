// Windows local demonstration only. Never accept live payees or call a PSP.
import {randomBytes,createHash,createPublicKey,verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline/promises';
import {createPaySandbox,formatDemoAmount,PAYEES} from '../lib/quantic/pay-sandbox.mjs';
const pin=/^[a-f0-9]{64}$/;
const hash=b=>createHash('sha256').update(b).digest('hex');
const check=v=>{if(!v)throw Error('Native Pay simulation refused');};
const [binary,dir,s,d]=process.argv.slice(2);
check(process.platform==='win32'&&process.argv.length===6&&process.stdin.isTTY&&process.stdout.isTTY&&pin.test(s)&&pin.test(d));
function verifyNative(i,nonce,p){
 check(p?.realPaymentAuthorized===false&&p.signingPin===s&&p.pqPin===d&&p.intent?.Payee===i.payeeId&&p.intent?.Cents===i.cents&&p.intent?.Nonce===nonce&&p.intent?.Issued===i.createdAt&&p.intent?.Expires===i.expiresAt&&Date.now()<i.expiresAt);
 const point=Buffer.from(p.classicalPublic,'base64url');
 check(point.length===65&&point[0]===4);
 const ec=createPublicKey({key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},format:'jwk'});
 const der=Buffer.from(p.pqPublic,'base64url');
 const pq=createPublicKey({key:der,format:'der',type:'spki'});
 check(hash(ec.export({format:'der',type:'spki'}))===s&&hash(der)===d&&pq.asymmetricKeyType==='ml-dsa-65');
 const body=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payeeId,i.cents,'EUR',nonce,i.createdAt,i.expiresAt,false]));
 const cl=Buffer.from(p.classicalSignature,'base64url'),ds=Buffer.from(p.pqSignature,'base64url');
 check(cl.length===64&&ds.length===3309&&verify('sha256',body,{key:ec,dsaEncoding:'ieee-p1363'},cl)&&verify(null,body,pq,ds));
}
const engine=createPaySandbox(),rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});
try{
 console.log('QUANTIC PAY / COFFRE NATIF SEPARE / SIMULATION UNIQUEMENT');
 while(true){
  console.log('Solde fictif: '+formatDemoAmount(engine.snapshot().balanceCents));
  const pick=(await rl.question('1=commerce demo, 2=particulier demo, Q=quitter : ')).trim();
  if(pick.toLowerCase()==='q')break;
  if(!['1','2'].includes(pick))continue;
  let i;
  try{
   i=engine.prepare({payeeId:PAYEES[Number(pick)-1].id,amount:(await rl.question('Montant fictif : ')).trim()});
   const nonce=randomBytes(32).toString('hex');
   // Native process owns the interactive password and consent prompts.
   rl.pause();
   if(process.stdin.isRaw)process.stdin.setRawMode(false);
   let result;
   try{result=spawnSync(binary,['--sign-windows-pay-lab',dir,s,d,i.payeeId,String(i.cents),nonce,String(i.createdAt)],{shell:false,stdio:['inherit','pipe','inherit'],encoding:'utf8',maxBuffer:32768});}
   finally{if(process.stdin.isTTY)process.stdin.setRawMode(true);rl.resume();}
   check(result.status===0&&!result.error);
   verifyNative(i,nonce,JSON.parse(result.stdout));
   const receipt=engine.confirm(i.id);
   console.log('Double signature du coffre verifiee : '+formatDemoAmount(receipt.cents)+' / aucune valeur monetaire.');
  }catch{
   if(i)try{engine.cancel(i.id)}catch{}
   console.log('Simulation refusee ou interrompue.');
  }
 }
}finally{rl.close();}
