import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {mkdtemp,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
import {createPayScatteringClient} from '../lib/quantic/pay-scattering-client.mjs';
import {createPayQuorumFlow} from '../lib/quantic/pay-quorum-flow.mjs';
import {verifyHistoricalPayProof} from '../lib/quantic/pay-lab-checkpoint.mjs';
import {openPayWitnessStore} from '../lib/quantic/pay-witness-store.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const binary=process.env.QUANTIC_PAY_SCATTERING_TEST;
test('Pay client refuses nonlocal port and short credentials',()=>{
 assert.throws(()=>createPayScatteringClient({loopbackPort:'https://example.org',token:'x'.repeat(48)}));
 assert.throws(()=>createPayScatteringClient({loopbackPort:1234,token:'short'}));
});
test('synthetic Pay proof and fresh before/after quorum travel through native UDP Scattering, not mail routes',{skip:!binary||process.platform!=='linux',timeout:90000},async()=>{
 const dir=await realpath(await mkdtemp(join(tmpdir(),'pay-scattering-')));
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
 const scope={signingPin:sha(spki(ec)),pqPin:sha(spki(pq))};
 const j=ec.publicKey.export({format:'jwk'});
 const point=Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);
 const authorities=Array.from({length:4},(_,i)=>({key:generateKeyPairSync('ed25519'),pqKey:generateKeyPairSync('ml-dsa-65'),directory:join(dir,'witness-'+i),store:null}));
 const trustedAuthorities=authorities.map(w=>({pin:sha(spki(w.key)),publicKey:spki(w.key).toString('base64url'),pqPin:sha(spki(w.pqKey)),pqPublicKey:spki(w.pqKey).toString('base64url')}));
 function openWitness(w,createNew){return openPayWitnessStore({directory:w.directory,createNew,scope,authorityPrivateKey:w.key.privateKey,expectedAuthorityPin:sha(spki(w.key)),authorityPQPrivateKey:w.pqKey.privateKey,expectedAuthorityPQPin:sha(spki(w.pqKey))});}
 const token=randomBytes(32).toString('hex'),hits=[];
 let link;
 const server=createServer(async(req,res)=>{
  try{
   assert.equal(req.headers.authorization,'Bearer '+token);assert.equal(req.method,'POST');
   const parts=[];let n=0;for await(const b of req){n+=b.length;assert.ok(n<=32768);parts.push(b);}
   const x=JSON.parse(Buffer.concat(parts));assert.equal(x.simulationOnly,true);
   hits.push(req.url);
   let result;
   if(req.url==='/api/quantic/pay-lab/v1/checkpoint'){
    result={simulationOnly:true,attestations:authorities.map(w=>w.store.vote(x.checkpoint))};
   }else if(req.url==='/api/quantic/pay-lab/v1/submit'){
    verifyHistoricalPayProof(x.proof,scope);
    for(const w of authorities){w.store.append(x.proof,x.prior);w.store.close();w.store=openWitness(w,false);}
    result={simulationOnly:true,accepted:true,realPaymentAuthorized:false};
   }else throw Error('wrong route');
   const b=Buffer.from(JSON.stringify(result));res.writeHead(200,{'Content-Type':'application/json','Content-Length':b.length});res.end(b);
  }catch{res.writeHead(400);res.end('{}');}
 });
 try{
  for(const w of authorities)w.store=openWitness(w,true);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  link=await startNativeScatteringLink({dir:join(dir,'link'),binary:resolve(binary),relayPort:server.address().port,profile:'pay-lab'});
  const port=Number(new URL(link.url).port);
  const wrong=await fetch(link.url+'api/quantic/native/v1/send',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:'{}'});
  assert.equal(wrong.status,400);await wrong.text();assert.equal(hits.length,0);
  const carrier=createPayScatteringClient({loopbackPort:port,token});
  const flow=createPayQuorumFlow({scope,trustedAuthorities,...carrier,signProof:async intent=>{
   const b=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',scope.signingPin,scope.pqPin,intent.Payee,intent.Cents,'EUR',intent.Nonce,intent.Issued,intent.Expires,false]));
   return {intent,...scope,realPaymentAuthorized:false,classicalPublic:point.toString('base64url'),pqPublic:spki(pq).toString('base64url'),classicalSignature:sign('sha256',b,{key:ec.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,b,pq.privateKey).toString('base64url')};
  }});
  const result=await flow.confirm({payeeId:'demo-shop',amount:'2.50',explicitConsent:true});
  assert.equal(result.balanceCents,9750);assert.equal(result.witnessCount,4);assert.equal(result.realPaymentAuthorized,false);
  assert.deepEqual(hits,['/api/quantic/pay-lab/v1/checkpoint','/api/quantic/pay-lab/v1/submit','/api/quantic/pay-lab/v1/checkpoint']);
  assert.ok(authorities.every(w=>w.store.summary().count===1));
  await link.close();await assert.rejects(flow.confirm({payeeId:'demo-shop',amount:'1',explicitConsent:true}));assert.equal(flow.snapshot().halted,true);assert.equal(flow.snapshot().balanceCents,9750);
 }finally{await link?.close();for(const w of authorities)w.store?.close();server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true});}
});
