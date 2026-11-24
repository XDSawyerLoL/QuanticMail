import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createPayWitnessQuorumClient} from '../lib/quantic/pay-witness-quorum-client.mjs';
import {openNativePayRemoteFlow} from '../lib/quantic/pay-native-remote-flow.mjs';
import {createDigitalEuroLabAdapter} from '../lib/quantic/pay-iso20022-preview.mjs';
import {inspectInterruptedPay} from '../lib/quantic/pay-recovery-lab.mjs';
import {openPaySettlementLab} from '../lib/quantic/pay-settlement-lab.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
import {resolve} from 'node:path';
import {newPayCheckpointRequest,reconcilePayCheckpoint} from '../lib/quantic/pay-lab-checkpoint.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-witness-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
async function port(){
 const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;
}
for(const useCarrier of [false,true])test('four separate witness processes, durable restart and reconciliation '+(useCarrier?'over four native UDP links':'over local HTTP'),{skip:process.platform!=='linux'||(useCarrier&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:90000},async()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-process-'))),nodes=[],proofs=[],links=[];
 let ledger;
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
 const scope={signingPin:sha(spki(ec)),pqPin:sha(spki(pq))};
 const j=ec.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);
 async function start(n){
  n.proc=spawn(process.execPath,[script,'serve',n.file],{stdio:['ignore','pipe','pipe']});
  await new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>reject(Error('startup deadline')),8000);
   n.proc.once('error',e=>{clearTimeout(timer);reject(e)});
   n.proc.once('exit',()=>{clearTimeout(timer);reject(Error('witness stopped'))});
   n.proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY LAB')){clearTimeout(timer);resolve();}});
   n.proc.stderr.resume();
  });
 }
 async function stop(n){
  if(!n.proc||n.proc.exitCode!==null||n.proc.signalCode!==null)return;
  await new Promise(r=>{n.proc.once('exit',r);n.proc.kill();});
 }
 try{
  for(let i=0;i<4;i++){
   const w=generateKeyPairSync('ed25519'),wq=generateKeyPairSync('ml-dsa-65'),p=await port(),token=randomBytes(32).toString('hex'),file=join(root,'config-'+i+'.json'),keyFile=join(root,'key-'+i+'.pem'),pqKeyFile=join(root,'pq-key-'+i+'.pem');
   writeFileSync(keyFile,w.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(pqKeyFile,wq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   const n={file,loopbackPort:p,token,trusted:{pin:sha(spki(w)),publicKey:spki(w).toString('base64url'),pqPin:sha(spki(wq)),pqPublicKey:spki(wq).toString('base64url')}};
   writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(root,'store-'+i),scope,authorityKeyFile:keyFile,authorityPin:n.trusted.pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:n.trusted.pqPin,token,port:p}),{mode:0o600,flag:'wx'});
   execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});nodes.push(n);await start(n);
  }
  const trustedAuthorities=nodes.map(n=>n.trusted);
  if(useCarrier)for(let i=0;i<4;i++){
   const link=await startNativeScatteringLink({dir:join(root,'link-'+i),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:nodes[i].loopbackPort,profile:'pay-lab'});
   links.push(link);
  }
  const endpoints=nodes.map((n,i)=>({loopbackPort:useCarrier?Number(new URL(links[i].url).port):n.loopbackPort,token:n.token}));
  const carrier=()=>createPayWitnessQuorumClient(endpoints);
  const options={scope,trustedAuthorities,links:endpoints,readHistory:async()=>structuredClone(proofs),signNative:async intent=>{
   const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',scope.signingPin,scope.pqPin,intent.Payee,intent.Cents,'EUR',intent.Nonce,intent.Issued,intent.Expires,false]));
   const p={intent,...scope,realPaymentAuthorized:false,classicalPublic:point.toString('base64url'),pqPublic:spki(pq).toString('base64url'),classicalSignature:sign('sha256',b,{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,pq.privateKey).toString('base64url')};proofs.push(p);return p;
  }};
  let flow=await openNativePayRemoteFlow(options);
  const op={payeeId:'demo-shop',amount:'2.50',explicitConsent:true};
  assert.equal((await flow.confirm(op)).witnessCount,4);
  await Promise.all(nodes.map(stop));await Promise.all(nodes.map(start));
  const q=newPayCheckpointRequest(scope),attestations=await carrier().readVotes(q);
  assert.equal(reconcilePayCheckpoint({localProofs:proofs,request:q,trustedAuthorities,attestations}).proofCount,1);
  assert.throws(()=>reconcilePayCheckpoint({localProofs:[],request:q,trustedAuthorities,attestations}));
  await assert.rejects(openNativePayRemoteFlow({...options,readHistory:async()=>[]}));
  const adapter=createDigitalEuroLabAdapter();
  const view=adapter.preview({localProofs:proofs,nonce:proofs[0].intent.Nonce,request:q,trustedAuthorities,attestations});
  assert.equal(view.instructedAmount.value,'2.50');assert.equal(view.transmittable,false);assert.equal(view.realPaymentAuthorized,false);assert.equal(view.settlementVerified,false);assert.equal(view.evidence.witnessCount,4);
  assert.throws(()=>adapter.preview({localProofs:[],nonce:proofs[0].intent.Nonce,request:q,trustedAuthorities,attestations}));
  assert.throws(()=>adapter.submit(view));assert.throws(()=>adapter.settle(view));
  const recovery={localProofs:proofs,nonce:proofs[0].intent.Nonce,request:q,trustedAuthorities,attestations};
  assert.equal(inspectInterruptedPay(recovery).state,'quorum-matches-complete-history');
  assert.equal(inspectInterruptedPay({...recovery,attestations:attestations.slice(0,2)}).state,'unresolved');
  const settlementOptions={directory:join(root,'central-lab'),scope,trustedAuthorities};
  ledger=openPaySettlementLab({...settlementOptions,createNew:true});
  const args={localProofs:proofs,nonce:proofs[0].intent.Nonce,request:q,attestations};
  assert.throws(()=>ledger.settle({...args,attestations:attestations.slice(0,2)}));
  const receipt=ledger.settle(args);assert.equal(receipt.status,'LAB_SETTLED');assert.equal(receipt.realPaymentAuthorized,false);
  assert.deepEqual(ledger.balances(),{wallet:9750,merchant:250,person:0,total:10000,simulationOnly:true,redeemable:false});
  ledger.close();ledger=openPaySettlementLab(settlementOptions);
  assert.deepEqual(ledger.lookup(args.nonce),receipt);assert.deepEqual(ledger.settle(args),receipt);assert.equal(ledger.balances().merchant,250);
  flow=await openNativePayRemoteFlow(options);assert.equal(flow.snapshot().balanceCents,9750);
  await stop(nodes[3]);assert.equal((await flow.confirm(op)).witnessCount,3);
  await stop(nodes[2]);await assert.rejects(flow.confirm(op));assert.equal(flow.snapshot().balanceCents,9500);assert.equal(flow.snapshot().halted,true);assert.equal(proofs.length,2);
 }finally{ledger?.close();await Promise.all(links.map(x=>x.close()));await Promise.all(nodes.map(stop));rmSync(root,{recursive:true,force:true});}
});
