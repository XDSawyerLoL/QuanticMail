import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign,X509Certificate} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {realpathSync,mkdtempSync,rmSync,writeFileSync,readFileSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {openShardedPayLab} from '../lib/quantic/pay-sharded-lab.mjs';
import {openDurableShard} from '../lib/quantic/pay-sharded-durable-lab.mjs';
import {openRemoteShardWitnessCoordinatorLab} from '../lib/quantic/pay-shard-witness-mtls-coordinator-lab.mjs';
import {openPayWitnessMtlsClientLab} from '../lib/quantic/pay-witness-mtls-lab.mjs';
import {openRemoteCrossShardRecoveryWorkerLab} from '../lib/quantic/pay-cross-shard-remote-recovery-worker-lab.mjs';
const runner=fileURLToPath(new URL('../scripts/quantic-pay-witness-node-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=x=>sha(Buffer.from(JSON.stringify(x)));
function keys(type='ed25519'){
 const cl=type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),
  pq=generateKeyPairSync('ml-dsa-65');
 const a=cl.publicKey.export({format:'der',type:'spki'}),b=pq.publicKey.export({format:'der',type:'spki'});
 return {cl,pq,pub:{pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')}};
}
const creds=k=>({authorityPin:k.pub.pin,classicalPrivateKey:k.cl.privateKey,pqPrivateKey:k.pq.privateKey});
test('eight network witness processes resume an atomic cross-shard payment after receiver outage',{skip:process.platform!=='linux',timeout:120000},async t=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'quantic-mtls-settlement-'))),children=[],voters=[],validators=[];
 let sourceDb=null,destDb=null,worker=null;
 const secret=(name,content)=>writeFileSync(join(root,name),content,{mode:0o600});
 const openssl=(...args)=>execFileSync('openssl',args,{cwd:root,stdio:'pipe'});
 const pem=name=>readFileSync(join(root,name));
 try{
  openssl('req','-new','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=Quantic remote payment lab CA',
   '-days','1','-keyout','ca.key','-out','ca.crt');
  chmodSync(join(root,'ca.key'),0o600);chmodSync(join(root,'ca.crt'),0o600);
  function issue(name,server=false){
   openssl('req','-new','-newkey','rsa:2048','-nodes','-subj',server?'/CN=localhost':'/CN='+name,
    '-keyout',name+'.key','-out',name+'.csr');
   secret(name+'.ext',server?
    'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n':
    'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n');
   openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key',
    '-CAcreateserial','-days','1','-out',name+'.crt','-extfile',name+'.ext','-sha256');
   chmodSync(join(root,name+'.key'),0o600);chmodSync(join(root,name+'.crt'),0o600);
   return {key:pem(name+'.key'),cert:pem(name+'.crt'),ca:pem('ca.crt'),
    pin:sha(new X509Certificate(pem(name+'.crt')).raw)};
  }
  const controller=issue('settlement-client');
  const serverCerts=Array.from({length:8},(_,i)=>issue('node-'+i,true));
  const east='demo-east',west='demo-west',keysA=Array.from({length:16},()=>keys()),
   keysB=Array.from({length:16},()=>keys()),witnessA=Array.from({length:4},()=>keys()),
   witnessB=Array.from({length:4},()=>keys()),alice=keys('ec'),bob=keys('ec');
  const config={shards:[{id:east,authorities:keysA.map(k=>k.pub)},
   {id:west,authorities:keysB.map(k=>k.pub)}],
   wallets:[{id:'demo-alice',shard:east,initial:1000,publicKey:alice.pub.publicKey,pqPublicKey:alice.pub.pqPublicKey},
    {id:'demo-shop',shard:west,initial:0,publicKey:bob.pub.publicKey,pqPublicKey:bob.pub.pqPublicKey}]};
  const mode={reservationsEnabled:true,crossShardAtomicEnabled:true,inboundPreparationEnabled:true};
  const ledger=openShardedPayLab(config,mode),source=ledger.openShard(east),target=ledger.openShard(west);
  sourceDb=openDurableShard({config,shard:east,directory:join(root,'source'),createNew:true,...mode});
  destDb=openDurableShard({config,shard:west,directory:join(root,'target'),createNew:true,...mode});
  function certify(chain,db,ops,committee){
   const p=chain.proposal(ops),nodes=committee.slice(0,11).map(k=>chain.openAuthority(creds(k))),
    prepared={scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.prepare(ops))},
    certificate={prepared,commit:{scope:p.scope,round:0,value:p.value,votes:nodes.map(n=>n.commit(prepared))}};
   assert.deepEqual(db.finalize(ops,certificate),chain.finalize(ops,certificate));
   return db.recoverReceipts(db.snapshot().height);
  }
  function walletProof(amount){
   const intent={network:ledger.network,payer:'demo-alice',payee:'demo-shop',
    amount,nonce:randomBytes(32).toString('hex')},msg=ledger.intentBytes(intent);
   return {intent,signature:sign('sha256',msg,{key:alice.cl.privateKey,
    dsaEncoding:'ieee-p1363'}).toString('base64url'),
    pqSignature:sign(null,msg,alice.pq.privateKey).toString('base64url')};
  }
  function approval(p){
   const i=p.intent,issued=Date.now(),expires=issued+120000,
    spki=alice.cl.publicKey.export({type:'spki',format:'der'}),
    pq=alice.pq.publicKey.export({type:'spki',format:'der'}),
    jwk=alice.cl.publicKey.export({format:'jwk'}),
    point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),
    s=sha(spki),d=sha(pq),intent={Payee:i.payee,Cents:i.amount,Nonce:i.nonce,Issued:issued,Expires:expires},
    message=Buffer.from(JSON.stringify(['quantic-pay-native-simulation/v1',s,d,i.payee,i.amount,
     'EUR',i.nonce,issued,expires,false]));
   return {intent,signingPin:s,pqPin:d,classicalSignature:sign('sha256',message,
     {key:alice.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),
    pqSignature:sign(null,message,alice.pq.privateKey).toString('base64url'),
    classicalPublic:point.toString('base64url'),pqPublic:pq.toString('base64url'),realPaymentAuthorized:false};
  }
  async function launch(index,createNew){
   const shard=index<4?east:west,k=(index<4?witnessA:witnessB)[index%4];
   secret('node-'+index+'.classical.pem',k.cl.privateKey.export({type:'pkcs8',format:'pem'}));
   secret('node-'+index+'.pq.pem',k.pq.privateKey.export({type:'pkcs8',format:'pem'}));
   const conf='node-'+index+'.json';
   secret(conf,JSON.stringify({config,options:mode,shard,
    witnesses:(index<4?witnessA:witnessB).map(x=>x.pub),
    credentials:{pin:k.pub.pin,classicalKeyPath:join(root,'node-'+index+'.classical.pem'),
     pqKeyPath:join(root,'node-'+index+'.pq.pem')},
    identity:{keyPath:join(root,'node-'+index+'.key'),
     certPath:join(root,'node-'+index+'.crt'),caPath:join(root,'ca.crt')},
    directory:join(root,'witness-'+index),createNew,host:'127.0.0.1',port:0,
    allowedClientCertPins:[controller.pin]}));
   const processNode=spawn(process.execPath,[runner],{
    env:{...process.env,QUANTIC_PAY_WITNESS_CONFIG:join(root,conf)},stdio:['ignore','pipe','pipe']});
   children.push(processNode);
   let out='',error='',ready=null;
   processNode.stderr.setEncoding('utf8');processNode.stderr.on('data',s=>error+=s);
   processNode.stdout.setEncoding('utf8');processNode.stdout.on('data',s=>{
    out+=s;let idx;
    while((idx=out.indexOf('\n'))>=0){
     const line=out.slice(0,idx);out=out.slice(idx+1);
     if(line){const record=JSON.parse(line);if(record.event==='ready')ready=record;}
    }
   });
   const started=Date.now();
   while(!ready&&Date.now()-started<15000){
    if(processNode.exitCode!==null)throw Error('remote witness crashed: '+error);
    await new Promise(resolve=>setTimeout(resolve,25));
   }
   assert.ok(ready,'witness startup timeout: '+error);
   assert.equal(ready.witnessPin,k.pub.pin);
   const client=openPayWitnessMtlsClientLab({url:'https://127.0.0.1:'+ready.port+'/v1/witness',
    credentials:{key:controller.key,cert:controller.cert,ca:controller.ca},
    serverCertPin:serverCerts[index].pin});
   return {processNode,client};
  }
  async function stop(p){
   if(p.exitCode!==null)return;
   const done=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('witness node did not close')),8000);
    p.once('close',()=>{clearTimeout(timer);resolve();});
   });
   p.kill('SIGTERM');await done;
  }
  const servers=[];
  for(let i=0;i<8;i++)servers.push(await launch(i,true));
  const clientsA=servers.slice(0,4).map(s=>s.client),clientsB=servers.slice(4).map(s=>s.client);
  const sourceBridge=openRemoteShardWitnessCoordinatorLab({config,options:mode,shard:east,
   witnesses:witnessA.map(w=>w.pub),clients:clientsA});
  const destBridge=openRemoteShardWitnessCoordinatorLab({config,options:mode,shard:west,
   witnesses:witnessB.map(w=>w.pub),clients:clientsB});
  const p=walletProof(600);
  certify(source,sourceDb,[{kind:'reserve',proof:p}],keysA);
  await sourceBridge.synchronize(sourceDb);
  const sourceAnchor=sourceDb.snapshot(),sourceCommit={
   checkpoint:sourceDb.checkpoint(),anchor:{network:ledger.network,shard:east,
    height:sourceAnchor.height,root:sourceAnchor.root}};
  certify(target,destDb,[{kind:'prepare-inbound',proof:p,
   sourceCheckpoint:sourceCommit.checkpoint,sourceAnchor:sourceCommit.anchor}],keysB);
  await destBridge.synchronize(destDb);
  const dstate=destDb.snapshot(),ready={checkpoint:destDb.checkpoint(),
   anchor:{network:ledger.network,shard:west,height:dstate.height,root:dstate.root}};
  const decisionLab=ledger.preparedDecision(p,ready);
  const participants=keysA.slice(0,11).map((k,i)=>{
   const n=decisionLab.openAuthority({directory:join(root,'decision-'+i),
    createNew:true,credentials:creds(k)});voters.push(n);return n;
  });
  const prepared={scope:decisionLab.scope,round:0,
   value:decisionLab.value('commit'),votes:participants.map(n=>n.prepare('commit'))};
  const decision={outcome:'commit',ready,certificate:{prepared,
   commit:{scope:decisionLab.scope,round:0,value:decisionLab.value('commit'),
    votes:participants.map(n=>n.commit('commit',prepared))}}};
  certify(source,sourceDb,[{kind:'capture',proof:p,approval:approval(p),decision}],keysA);
  await sourceBridge.synchronize(sourceDb);
  assert.equal(sourceDb.snapshot().balances['demo-alice'],400);
  assert.equal(destDb.snapshot().balances['demo-shop'],0);
  for(let i=0;i<11;i++)validators.push(openDurableShard({config,shard:west,
   directory:join(root,'validator-'+i),credentials:creds(keysB[i]),createNew:true,...mode}));
  // Make the recipient witness quorum unavailable (2/4) until recovery starts.
  await stop(servers[4].processNode);await stop(servers[5].processNode);
  worker=openRemoteCrossShardRecoveryWorkerLab({ledger,config,
   source:sourceDb,destination:destDb,sourceShard:east,destinationShard:west,
   sourceBridge,destinationBridge:destBridge,destinationValidators:validators,intervalMs:100});
  assert.equal((await worker.start()).status,'deferred');
  assert.equal(destDb.snapshot().balances['demo-shop'],0);
  servers[4]=await launch(4,false);clientsB[0]=servers[4].client;
  for(let i=0;i<50&&destDb.snapshot().balances['demo-shop']===0;i++)
   await new Promise(resolve=>setTimeout(resolve,100));
  assert.equal(destDb.snapshot().balances['demo-shop'],600,JSON.stringify(worker.last()));
  assert.equal(destDb.snapshot().pendingInbound,0);
  await stop(servers[5].processNode).catch(()=>{});
  servers[5]=await launch(5,false);clientsB[1]=servers[5].client;
  assert.equal((await worker.runOnce()).status,'caught-up');
  assert.equal((await destBridge.fresh(destDb.snapshot())).witnesses,4);
  assert.equal((await worker.runOnce()).processed,0);
  assert.equal(worker.stats().claimed,1);
  await worker.close();
  // A fully restarted settlement controller uses persisted financial blocks;
  // it must not re-create the cross-shard COMMIT or issue a second credit.
  worker=openRemoteCrossShardRecoveryWorkerLab({ledger,config,source:sourceDb,
   destination:destDb,sourceShard:east,destinationShard:west,
   sourceBridge,destinationBridge:destBridge,destinationValidators:validators,intervalMs:100});
  assert.equal((await worker.start()).status,'caught-up');
  assert.equal(worker.stats().claimed,0);
  assert.equal(destDb.snapshot().balances['demo-shop'],600);
  assert.equal(sourceDb.snapshot().balances['demo-alice']+destDb.snapshot().balances['demo-shop'],1000);
  t.diagnostic('EIGHT_WITNESS_REMOTE_SETTLEMENT_V1 '+JSON.stringify({witnessProcesses:8,
   sourceQuorum:4,destinationQuorum:4,recipientOutageRefused:true,
   recoveredCredit:600,duplicateCredit:0,workerRestartIdempotent:true,simulationOnly:true}));
 }finally{
  try{await worker?.close();}catch{}
  for(const n of [...validators,...voters])try{n.close();}catch{}
  try{sourceDb?.close();}catch{}try{destDb?.close();}catch{}
  for(const child of children)try{child.kill('SIGKILL');}catch{}
  rmSync(root,{recursive:true,force:true});
 }
});
