import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {packShardReceipts,unpackShardReceipts} from '../lib/quantic/pay-shard-receipt-wire-lab.mjs';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
test('four separate shard processes certify batches in parallel then exchange certified cross-shard claims',{timeout:120000},async t=>{
 const ids=['demo-east','demo-west','demo-north','demo-south'],accounts=['demo-alice','demo-bob','demo-carol','demo-dan'],keys=ids.map(()=>Array.from({length:16},()=>key('ed25519'))),wallets=accounts.map(()=>key('ec'));
 const config={shards:ids.map((id,i)=>({id,authorities:keys[i].map(k=>k.pub)})),wallets:accounts.map((id,i)=>({id,shard:ids[i],initial:1000,publicKey:wallets[i].pub.publicKey,pqPublicKey:wallets[i].pub.pqPublicKey}))};
 const lab=openShardedPayLab(config),children=[],clients=[];let id=0;
 function client(){
  const p=fork(fileURLToPath(new URL('./helpers/pay-shard-process.mjs',import.meta.url)),[],{execArgv:[],stdio:['ignore','ignore','ignore','ipc']});children.push(p);
  const pending=new Map();
  const abort=e=>{for(const {reject,timer} of pending.values()){clearTimeout(timer);reject(e);}pending.clear();};
  p.on('error',abort);p.on('exit',()=>abort(Error('partition exited')));
  p.on('message',m=>{const q=pending.get(m.id);if(!q)return;pending.delete(m.id);clearTimeout(q.timer);if(m.ok)q.resolve(m.result);else q.reject(Error('partition rejected operation'));});
  return msg=>new Promise((resolve,reject)=>{const n=++id,timer=setTimeout(()=>{pending.delete(n);reject(Error('partition timed out'));},45000);pending.set(n,{resolve,reject,timer});p.send({...msg,id:n},e=>{if(e){clearTimeout(timer);pending.delete(n);reject(e);}});});
 }
 const total=rows=>rows.reduce((a,r)=>a+Object.values(r.snapshot.balances).reduce((b,n)=>b+n,0),0);
 function tx(i){const intent={network:lab.network,payer:accounts[i],payee:accounts[(i+1)%4],amount:1,nonce:randomBytes(32).toString('hex')},b=lab.intentBytes(intent),k=wallets[i];return {kind:'debit',proof:{intent,signature:sign('sha256',b,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,k.pq.privateKey).toString('base64url')}};}
 try{
  for(let i=0;i<4;i++)clients.push(client());
  const init=await Promise.all(clients.map((c,i)=>c({op:'init',config,shard:ids[i],keys:keys[i].slice(0,11).map(k=>({pin:k.pub.pin,cl:k.cl.privateKey.export({format:'der',type:'pkcs8'}).toString('base64url'),pq:k.pq.privateKey.export({format:'der',type:'pkcs8'}).toString('base64url')}))})));
  assert.equal(new Set(init.map(x=>x.pid)).size,4);assert.equal(total(init),4000);
  const input=ids.map((_,i)=>Array.from({length:8},()=>tx(i))),start=performance.now();
  const debits=await Promise.all(clients.map((c,i)=>c({op:'certify',operations:input[i]}))),debitMs=performance.now()-start;
  assert.equal(total(debits),3968);for(const d of debits)assert.equal(d.receipts.length,8);
  const bundles=debits.map(d=>packShardReceipts(d.receipts));
  const decoded=bundles.map(unpackShardReceipts);
  for(let i=0;i<4;i++){
   assert.deepEqual(decoded[i],debits[i].receipts);
   for(const r of decoded[i])lab.verifyDebit(r);
   assert.ok(bundles[i].length<Buffer.byteLength(JSON.stringify(debits[i].receipts))*.15);
   assert.throws(()=>unpackShardReceipts(bundles[i].subarray(0,-1)));
   assert.throws(()=>unpackShardReceipts(Buffer.concat([bundles[i],Buffer.alloc(1)])));
   assert.throws(()=>packShardReceipts([decoded[i][0],decoded[i][0]]));
   const tampered=Buffer.from(bundles[i]);tampered[tampered.length-1]^=1;
   assert.throws(()=>lab.verifyDebit(unpackShardReceipts(tampered).at(-1)));
  }
  const jsonBytes=debits.reduce((n,d)=>n+Buffer.byteLength(JSON.stringify(d.receipts)),0),binaryBytes=bundles.reduce((n,b)=>n+b.length,0);
  t.diagnostic('SHARD_RECEIPT_BUNDLE_V1 '+JSON.stringify({transfers:32,jsonBytes,binaryBytes,reduction:1-binaryBytes/jsonBytes}));
  const claims=ids.map((_,i)=>decoded[(i+3)%4].map(receipt=>({kind:'claim',receipt})));
  const t1=performance.now(),credits=await Promise.all(clients.map((c,i)=>c({op:'certify',operations:claims[i]}))),creditMs=performance.now()-t1;
  assert.equal(total(credits),4000);for(const [i,c] of credits.entries()){assert.equal(c.snapshot.height,2);assert.equal(c.snapshot.balances[accounts[i]],1000);}
  await Promise.all(clients.map((c,i)=>assert.rejects(c({op:'certify',operations:claims[i]}))));
  t.diagnostic('SHARDED_PARALLEL_V1 '+JSON.stringify({processes:4,configuredAuthorities:64,activeAuthorities:44,transfers:32,certifiedOperations:64,debitMs,creditMs,totalMs:debitMs+creditMs,simulationOnly:true}));
 }finally{await Promise.all(children.map(p=>new Promise(r=>{if(p.exitCode!==null||p.signalCode!==null)return r();p.once('close',r);p.kill();})));}
});
