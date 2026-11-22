// Single-host real UDP R&D fixture: one remote-path voter, ten local voters.
// The controller shares synthetic configuration and exact message sizes only.
// No production framing, provisioning, persistent state, or physical WAN claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {reliableCellStream,POLICY} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {cellKey} from '../labs/quantic-native/scattering/scattering-cell.mjs';
import {openPayBatchLab} from '../lib/quantic/pay-batch-lab.mjs';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
const binary=process.env.QUANTIC_PAY_SCATTERING_TEST;
const sha=b=>createHash('sha256').update(b).digest('hex');
function key(type){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});
 return {cl,pq,pub:{pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')}};
}
const raw=x=>Buffer.from(JSON.stringify(x));
const parse=b=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));
test('100 hybrid-signed synthetic transactions cross native UDP to one independent verifier with 11/16 certification',{skip:!binary||process.platform!=='linux',timeout:150000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'pay-batch-udp-')),dirs=[join(root,'a'),join(root,'b')],sockets=[],cells=[],children=[],failures=[];
 let closing=false,wrongSize=0;const received=[0,0],metrics={},sequence=[0,0];
 try{
  await Promise.all(dirs.map(d=>mkdir(d,{mode:0o700})));
  const a=key('ec'),b=key('ec'),witnesses=Array.from({length:16},()=>key('ed25519'));
  const config={admissionPolicy:'round-v3',wallets:[{id:'demo-alice',initialCents:10000,...a.pub},{id:'demo-bob',initialCents:0,...b.pub}],witnesses:witnesses.map(w=>w.pub)};
  const chain=createRoundCirculationLab(config),labs=[openPayBatchLab({config}),openPayBatchLab({config})];
  const now=1000000,proofs=Array.from({length:100},()=>{
   const intent=chain.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:1,nonce:randomBytes(32).toString('hex'),now}),bytes=chain.transcript(intent);
   return {intent,signature:sign('sha256',bytes,{key:a.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,bytes,a.pq.privateKey).toString('base64url')};
  });
  const proposed=labs[0].propose(proofs,now);
  const authorities=witnesses.slice(0,11).map((w,i)=>(i===10?labs[1]:labs[0]).openAuthority({authorityPin:w.pub.pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey}));
  const secret=randomBytes(32),epoch=randomBytes(32),ab=cellKey(secret,epoch,'a-b'),ba=cellKey(secret,epoch,'b-a');secret.fill(0);epoch.fill(0);
  for(let i=0;i<2;i++){
   const c=reliableCellStream({sendKey:i?ba:ab,recvKey:i?ab:ba,dir:dirs[i],compactPacing:true,dualProofPacing:true});
   c.stream.on('error',e=>failures.push(e.message));cells.push(c);
   const sock=createSocket('udp4');sockets.push(sock);
   await new Promise((res,rej)=>{sock.once('error',rej);sock.bind(0,'127.0.0.1',res);});
   sock.on('message',m=>{received[i]++;if(m.length!==168)wrongSize++;c.receive(m);});
  }
  ab.fill(0);ba.fill(0);
  for(let i=0;i<2;i++){
   const p=spawn(resolve(binary),['-target','127.0.0.1:'+sockets[1-i].address().port,'-queue-dir',dirs[i],'-period-us','5000','-poll','10ms','-wait-mode','native'],{stdio:'ignore'});children.push(p);
   p.on('error',e=>failures.push(e.message));p.on('exit',()=>{if(!closing)failures.push('pacer exited');});
  }
  await new Promise(r=>setTimeout(r,400));
  // Exact length is fixture knowledge, not a network API. Transport ACK is volatile.
  async function carry(from,label,obj){
   const bytes=raw(obj),src=cells[from].stream,dst=cells[1-from].stream;
   const needed=Math.ceil(bytes.length/POLICY.payload);
   assert.ok(sequence[from]+needed<=POLICY.maxSeq);sequence[from]+=needed;
   assert.ok(bytes.length>0&&bytes.length<=600000);
   const chunks=[];let count=0,t0=performance.now(),onData;
   const read=new Promise((res,rej)=>{
    onData=b=>{count+=b.length;if(count>bytes.length){rej(Error('fixture overflow'));return;}chunks.push(b);if(count===bytes.length)res(Buffer.concat(chunks,count));};
    dst.on('data',onData);
   });
   let timer;const deadline=new Promise((_,rej)=>{timer=setTimeout(()=>rej(Error('fixture transfer deadline')),70000);});
   const write=(async()=>{for(let o=0;o<bytes.length;o+=8192)await new Promise((res,rej)=>src.write(bytes.subarray(o,o+8192),e=>e?rej(e):res()));})();
   try{
    const [got]=await Promise.race([Promise.all([read,write]),deadline]);
    assert.deepEqual(got,bytes);assert.equal(failures.length,0);
    metrics[label]={bytes:bytes.length,ms:performance.now()-t0};return parse(got);
   }finally{clearTimeout(timer);dst.off('data',onData);}
  }
  const input=await carry(0,'batch',{proofs,time:now,value:proposed.value});
  assert.equal(labs[1].propose(input.proofs,input.time).value,proposed.value);
  const local=authorities.slice(0,10),remote=authorities[10];
  const rv=await carry(1,'prepareVote',remote.prepare(input));
  const prepared={scope:labs[0].scope,round:0,value:proposed.value,votes:[...local.map(n=>n.prepare({proofs,time:now,value:proposed.value})),rv]};
  const remotePrepared=await carry(0,'prepareCertificate',prepared);
  const cv=await carry(1,'commitVote',remote.commit(remotePrepared));
  const commit={scope:labs[0].scope,round:0,value:proposed.value,votes:[...local.map(n=>n.commit(prepared)),cv]};
  const cert={prepared,commit};
  const remoteFinal=await carry(0,'finalCertificate',cert);
  remote.learn(remoteFinal);for(const n of local)n.learn(cert);
  const r=proposed.receipt(99,cert);assert.equal(labs[1].verifyReceipt(r).included,true);
  assert.deepEqual(proposed.balances,{'demo-alice':9900,'demo-bob':100});
  assert.equal(wrongSize,0);assert.equal(failures.length,0);assert.ok(received.every(n=>n>0));
  const total=Object.values(metrics).reduce((s,v)=>s+v.ms,0);
  t.diagnostic('BATCH_NATIVE_V1 '+JSON.stringify({count:100,remoteVoters:1,localVoters:10,metrics,transferMs:total,transferOnlyTransactionsPerSecond:100000/total,received,wrongSize,sequence,simulationOnly:true}));
 }finally{
  closing=true;for(const c of cells)c.stream.destroy();for(const s of sockets)s.close();
  await Promise.all(children.map(p=>new Promise(r=>{if(p.exitCode!==null||p.signalCode!==null)return r();p.once('close',r);p.kill();})));
  await rm(root,{recursive:true,force:true});
 }
});
