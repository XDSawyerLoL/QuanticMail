import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,X509Certificate,randomBytes} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {mkdtempSync,realpathSync,rmSync,writeFileSync,readFileSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
import {openRemoteShardWitnessCoordinatorLab} from '../lib/quantic/pay-shard-witness-mtls-coordinator-lab.mjs';
import {openPayWitnessMtlsClientLab} from '../lib/quantic/pay-witness-mtls-lab.mjs';
const runner=fileURLToPath(new URL('../scripts/quantic-pay-witness-node-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=x=>sha(Buffer.from(JSON.stringify(x)));
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
function witnessKeys(){
 const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
function walletKeys(){
 const cl=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({type:'spki',format:'der'}),b=pq.publicKey.export({type:'spki',format:'der'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
test('four independent witness processes enforce pinned mutual TLS, certified pre-votes and 3/4 liveness',{skip:process.platform!=='linux',timeout:120000},async t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-remote-mtls-'))),children=[];
 let db;
 const cmd=(...args)=>execFileSync('openssl',args,{cwd:root,stdio:'pipe'});
 const secret=(p,s)=>writeFileSync(join(root,p),s,{mode:0o600});
 const pem=p=>readFileSync(join(root,p));
 try{
  cmd('req','-new','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=Quantic Pay Test CA',
   '-days','1','-keyout','ca.key','-out','ca.crt');
  chmodSync(join(root,'ca.key'),0o600);chmodSync(join(root,'ca.crt'),0o600);
  function issue(name,server=false){
   cmd('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+(server?'localhost':name),
    '-keyout',name+'.key','-out',name+'.csr');
   secret(name+'.ext',server
    ?'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n'
    :'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n');
   cmd('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key',
    '-CAcreateserial','-days','1','-out',name+'.crt','-extfile',name+'.ext','-sha256');
   chmodSync(join(root,name+'.key'),0o600);chmodSync(join(root,name+'.crt'),0o600);
   return {key:pem(name+'.key'),cert:pem(name+'.crt'),ca:pem('ca.crt'),
    pin:sha(new X509Certificate(pem(name+'.crt')).raw)};
  }
  const controller=issue('controller'),intruder=issue('intruder');
  const serverCerts=Array.from({length:4},(_,i)=>issue('witness-'+i,true));
  const authorities=Array.from({length:16},witnessKeys),other=Array.from({length:16},witnessKeys),wk=Array.from({length:4},witnessKeys),alice=walletKeys(),bob=walletKeys();
  const east='demo-east',west='demo-west';
  const config={shards:[{id:east,authorities:authorities.map(k=>k.pub)},{id:west,authorities:other.map(k=>k.pub)}],
   wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},
    {id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const options={reservationsEnabled:true},ledger=openShardedPayLab(config,options);
  db=openDurableShard({config,shard:east,directory:join(root,'shard'),createNew:true,...options});
  const chain=ledger.openShard(east);
  function certifyReserve(amount){
   const intent={network:ledger.network,payer:'demo-alice',payee:'demo-shop',amount,nonce:randomBytes(32).toString('hex')};
   const msg=ledger.intentBytes(intent);
   const proof={intent,signature:sign('sha256',msg,{key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),
    pqSignature:sign(null,msg,alice.pq.privateKey).toString('base64url')};
   const ops=[{kind:'reserve',proof}],p=chain.proposal(ops),
    voters=authorities.slice(0,11).map(k=>chain.openAuthority(creds(k))),
    prepared={scope:p.scope,round:0,value:p.value,votes:voters.map(k=>k.prepare(ops))},
    cert={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:voters.map(k=>k.commit(prepared))}};
   assert.deepEqual(chain.finalize(ops,cert),db.finalize(ops,cert));
  }
  async function launch(i,createNew){
   const k=wk[i];
   const classical='witness-'+i+'.sign.key',pq='witness-'+i+'.pq.key';
   secret(classical,k.cl.privateKey.export({type:'pkcs8',format:'pem'}));
   secret(pq,k.pq.privateKey.export({type:'pkcs8',format:'pem'}));
   const json='witness-'+i+'.config.json';
   secret(json,JSON.stringify({config,options,shard:east,witnesses:wk.map(x=>x.pub),
    credentials:{pin:k.pub.pin,classicalKeyPath:join(root,classical),pqKeyPath:join(root,pq)},
    identity:{keyPath:join(root,'witness-'+i+'.key'),certPath:join(root,'witness-'+i+'.crt'),
     caPath:join(root,'ca.crt')},
    directory:join(root,'witness-'+i+'-db'),createNew,host:'127.0.0.1',port:0,
    allowedClientCertPins:[controller.pin]}));
   const child=spawn(process.execPath,[runner],{env:{...process.env,QUANTIC_PAY_WITNESS_CONFIG:join(root,json)},
    stdio:['ignore','pipe','pipe']});
   children.push(child);
   let buffer='',stderr='';
   child.stderr.setEncoding('utf8');child.stderr.on('data',s=>stderr+=s);
   child.stdout.setEncoding('utf8');
   let ready=null;child.stdout.on('data',s=>{
    buffer+=s;let cut;
    while((cut=buffer.indexOf('\n'))>=0){
     const line=buffer.slice(0,cut);buffer=buffer.slice(cut+1);
     if(line){const item=JSON.parse(line);if(item.event==='ready')ready=item;}
    }
   });
   const started=Date.now();
   while(!ready&&Date.now()-started<15000){
    if(child.exitCode!==null)throw Error('witness failed: '+stderr);
    await new Promise(r=>setTimeout(r,25));
   }
   assert.ok(ready,'witness did not start: '+stderr);
   assert.equal(ready.witnessPin,k.pub.pin);
   const url='https://127.0.0.1:'+ready.port+'/v1/witness';
   const client=openPayWitnessMtlsClientLab({url,credentials:{key:controller.key,cert:controller.cert,ca:controller.ca},serverCertPin:serverCerts[i].pin});
   return {child,client,url};
  }
  async function stop(child){
   if(child.exitCode!==null)return;
   const finished=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('witness shutdown timed out')),10000);
    child.once('close',()=>{clearTimeout(timer);resolve();});
   });
   child.kill('SIGTERM');await finished;
  }
  const services=[];
  for(let i=0;i<4;i++)services.push(await launch(i,true));
  const clients=services.map(x=>x.client);
  const coordinator=openRemoteShardWitnessCoordinatorLab({config,options,shard:east,witnesses:wk.map(x=>x.pub),clients});
  assert.notEqual(services[0].child.pid,services[1].child.pid);
  const rejected=openPayWitnessMtlsClientLab({url:services[0].url,
   credentials:{key:intruder.key,cert:intruder.cert,ca:intruder.ca},serverCertPin:serverCerts[0].pin});
  await assert.rejects(()=>rejected.status(),'unauthorized but CA-signed client');
  const wrongPin=openPayWitnessMtlsClientLab({url:services[0].url,
   credentials:{key:controller.key,cert:controller.cert,ca:controller.ca},serverCertPin:'f'.repeat(64)});
  await assert.rejects(()=>wrongPin.status(),'pinned server identity mismatch');
  assert.equal((await clients[0].status()).height,0);
  certifyReserve(100);
  let cp=db.certifiedCheckpoint(1),h=cp.header,root1=hash(['quantic-shard-block/v1',
   h.network,h.shard,h.height,h.previous,h.operationsRoot,h.stateRoot]);
  const request={anchor:{epoch:0,height:0,root:h.previous,committee:coordinator.committee,tip:'0'.repeat(64)},mode:'vote',value:root1};
  const altered=structuredClone(cp);altered.header.stateRoot='f'.repeat(64);
  await assert.rejects(()=>clients[0].grantCertified(request,{checkpoint:altered}),
   'invalid financial QC must never lock the remote witness');
  assert.equal((await clients[0].status()).mode,'idle');
  assert.equal((await coordinator.synchronize(db)).witnesses,4);
  certifyReserve(150);
  await stop(services[0].child);
  assert.equal((await coordinator.synchronize(db)).witnesses,3);
  assert.equal((await coordinator.fresh(db.snapshot())).witnesses,3);
  await stop(services[1].child);
  await assert.rejects(()=>coordinator.fresh(db.snapshot()),'2/4 live witnesses must fail closed');
  // Reopen the exact original witness SQLite store in its own process.
  services[0]=await launch(0,false);clients[0]=services[0].client;
  assert.equal((await clients[0].status()).height,1);
  await assert.rejects(()=>coordinator.fresh(db.snapshot()),
   'a restarted stale witness must not substitute for a third current vote');
  // Restore one of the *current* witnesses; only then does a valid 3/4
  // signed tip reappear. The lagging server never claims newer state.
  services[1]=await launch(1,false);clients[1]=services[1].client;
  assert.equal((await coordinator.fresh(db.snapshot())).witnesses,3);
  assert.equal((await services[0].client.status()).root,root1);
  // Repair must be authorized by the recovering process's challenge and
  // a fresh 3-of-4 hybrid quorum, not merely a caller-provided stale tip.
  const cp2=db.certifiedCheckpoint(2),h2=cp2.header;
  const root2=hash(['quantic-shard-block/v1',h2.network,h2.shard,
   h2.height,h2.previous,h2.operationsRoot,h2.stateRoot]);
  const target={epoch:0,height:2,root:root2,committee:coordinator.committee,tip:'0'.repeat(64)};
  const steps=[{request:{anchor:request.anchor,mode:'vote',value:root1},
   proof:{checkpoint:cp}}];
  // The old height-1 block is not part of catch-up: prepare height 2.
  steps[0]={request:{anchor:{...request.anchor,height:1,root:root1},
    mode:'vote',value:root2},proof:{checkpoint:cp2}};
  const tampered=structuredClone(steps);tampered[0].proof.checkpoint.header.stateRoot='f'.repeat(64);
  await assert.rejects(()=>clients[0].beginRemoteCatchUp(target,tampered));
  assert.equal((await clients[0].status()).height,1);
  const challenge1=await clients[0].beginRemoteCatchUp(target,steps);
  assert.match(challenge1.challenge,/^[a-f0-9]{64}$/);
  const signed1=await Promise.all(clients.slice(1).map(peer=>peer.attestState(challenge1.challenge)));
  await assert.rejects(()=>clients[0].finishRemoteCatchUp('f'.repeat(64),signed1));
  assert.equal((await clients[0].status()).height,1);
  const challenge2=await clients[0].beginRemoteCatchUp(target,steps);
  const signed2=await Promise.all(clients.slice(1).map(peer=>peer.attestState(challenge2.challenge)));
  const forged=structuredClone(signed2);forged[2].status.root='f'.repeat(64);
  await assert.rejects(()=>clients[0].finishRemoteCatchUp(challenge2.challenge,forged));
  assert.equal((await clients[0].status()).height,1);
  const repaired=await coordinator.repairWitness(db,0);
  assert.equal(repaired.verifiedSteps,1);
  assert.equal((await clients[0].status()).height,2);
  assert.equal((await coordinator.fresh(db.snapshot())).witnesses,4);
  assert.equal((await coordinator.repairLagging(db)).repaired,0);
  t.diagnostic('REMOTE_WITNESS_MTLS_V1 '+JSON.stringify({independentProcesses:4,
   controllerAuthenticated:true,serverPins:4,untrustedClientRefused:true,
   malformedCertificatePreVoteRefused:true,threeOfFourLive:true,
   twoOfFourRefused:true,rolledBackOrLaggingOneDoesNotForgeTip:true,remoteWitnessRepaired:true,wrongChallengeRefused:true,simulationOnly:true}));
 }finally{
  for(const child of children)try{child.kill('SIGKILL');}catch{}
  try{db?.close();}catch{}
  rmSync(root,{recursive:true,force:true});
 }
});
