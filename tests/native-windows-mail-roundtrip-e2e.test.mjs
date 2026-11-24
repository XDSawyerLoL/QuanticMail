// A bounded synthetic integration gate. Actual Windows storage, DPAPI,
// Go/OpenSSL PQ cryptography, Node client, native pacers/sinks and mailbox core.
// The test-only trust fixture deliberately does NOT emulate production quorum
// authority, deployment, physical machines or the interactive desktop.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createSocket} from 'node:dgram';
import {spawn,execFileSync} from 'node:child_process';
import {randomBytes,createHash,createPublicKey,verify} from 'node:crypto';
import {mkdtemp,rm,readFile,realpath,open,rename} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {saveWindowsDraft} from '../desktop/native-windows-draft.mjs';
import {composeAndSendWindowsLab} from '../desktop/native-windows-integrated-mail.mjs';
import {runWindowsScatteringMail} from '../desktop/native-windows-mail-flow.mjs';
import {openReceipt} from '../desktop/native-receipt-store.mjs';
import {nativeSenderTranscript} from '../lib/quantic/native-identity-bridge.mjs';
import {nativeMailboxEntries,restoreNativeMailbox,normalizeNativeRecord,nativeRecordDigest,enqueueNativeRecord,pullNativeRecord,acknowledgeNativeRecord,recoverNativeRecord} from '../lib/quantic/native-mailbox.mjs';

const enabled=process.env.QUANTIC_WINDOWS_MAIL_E2E==='1';
const base='/api/quantic/native/v1/';
const hex=b=>createHash('sha256').update(b).digest('hex');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function freeUDP(){const s=createSocket('udp4');await new Promise((r,j)=>{s.once('error',j);s.bind(0,'127.0.0.1',r);});const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function checkedPath(name){assert.ok(process.env[name],name+' required');return resolve(process.env[name]);}

test('Windows actual PQ vaults, durable draft, native UDP relay, decrypt, receipt, restart and ACK recovery',{skip:!enabled,timeout:180000},async()=>{
 assert.equal(process.platform,'win32');
 const vault=checkedPath('QUANTIC_WINDOWS_VAULT_TEST'),pacer=checkedPath('QUANTIC_SCATTERING_NATIVE_TEST'),fixture=checkedPath('QUANTIC_WINDOWS_MAIL_FIXTURE');
 const pin=hex(await readFile(vault));
 const root=await realpath(await mkdtemp(join(process.env.QUANTIC_WINDOWS_TEST_ROOT??await realpath(tmpdir()),'qs-mail-e2e-')));
 const kids=[],endpoints=[];
 let server,relayPort,failAck=true,acks=0,relayRequests=0,processes=0;
 const snapshot=join(root,'relay-state.json');
 let peers,tokens;
 function invoke(stage,input='',draft=''){
  const out=execFileSync(fixture,['-test.run=^TestWindowsMailE2EFixture$','-test.count=1','-test.v'],{
   cwd:dirname(vault),env:{...process.env,QS_MAIL_E2E_ROOT:root,QS_MAIL_E2E_STAGE:stage,QS_MAIL_E2E_DRAFT:draft},
   input,encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:262144});
  processes++;
  const rows=out.split(/\r?\n/).filter(l=>l.startsWith('QS_FIXTURE:'));
  assert.equal(rows.length,1);
  return JSON.parse(rows[0].slice('QS_FIXTURE:'.length));
 }
 async function persist(){
  const f=await open(snapshot+'.tmp','w');
  try{await f.writeFile(JSON.stringify(nativeMailboxEntries()));await f.sync();}finally{await f.close();}
  await rename(snapshot+'.tmp',snapshot);
 }
 function verifyWire(w,peer){
  const point=Buffer.from(peer.signing,'base64url');
  const publicKey=createPublicKey({key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},format:'jwk'});
  const pq=createPublicKey({key:Buffer.from(peer.dsaPublic,'base64url'),type:'spki',format:'der'});
  const transcript=nativeSenderTranscript(w.context,w.envelope);
  assert.ok(verify('sha256',transcript,{key:publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(w.senderAuth.classicalSignature,'base64url')));
  assert.ok(verify(null,transcript,pq,Buffer.from(w.senderAuth.pqSignature,'base64url')));
 }
 function respond(res,status,body){
  const b=Buffer.from(JSON.stringify(body));res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length});res.end(b);
 }
 async function startRelay(port=0){
  server=createServer(async(req,res)=>{
   try{
    relayRequests++;
    const index=tokens.findIndex(t=>req.headers.authorization==='Bearer '+t);
    assert.ok(index>=0);const peer=peers[index];
    assert.equal(req.method,'POST');
    const parts=[];let length=0;
    for await(const c of req){length+=c.length;assert.ok(length<=32768);parts.push(c);}
    const body=JSON.parse(Buffer.concat(parts).toString('utf8')),op=req.url?.slice(base.length);
    assert.ok(req.url?.startsWith(base));
    if(op==='send'){
     const wire=normalizeNativeRecord(body);
     assert.equal(wire.context.from,peer.address);assert.equal(wire.context.fromDeviceId,peer.deviceId);
     assert.equal(wire.context.to,peers[1-index].address);assert.equal(wire.context.toDeviceId,peers[1-index].deviceId);
     verifyWire(wire,peer);
     const result=enqueueNativeRecord(wire);await persist();return respond(res,202,result);
    }
    assert.equal(body.address,peer.address);assert.equal(body.deviceId,peer.deviceId);
    if(op==='pull')return respond(res,200,{item:pullNativeRecord(peer.address,peer.deviceId)});
    if(op==='recover')return respond(res,200,{item:recoverNativeRecord(peer.address,peer.deviceId,body.id,body.digest)});
    if(op==='ack'){
     if(failAck){failAck=false;return respond(res,503,{error:'synthetic interruption before ACK commit'});}
     const result=acknowledgeNativeRecord(peer.address,peer.deviceId,body.id,body.digest);
     await persist();acks++;return respond(res,200,result);
    }
    return respond(res,400,{error:'unknown operation'});
   }catch{return respond(res,403,{error:'synthetic relay refused'});}
  });
  await new Promise((r,j)=>{server.once('error',j);server.listen(port,'127.0.0.1',r);});
  return server.address().port;
 }
 async function stopRelay(){if(!server)return;server.closeAllConnections();await new Promise(r=>server.close(r));server=undefined;}
 async function transport(name){
  const shared={labOnly:true,secretHex:randomBytes(32).toString('hex'),epochHex:randomBytes(32).toString('hex'),recvPort:0};
  const pair=[],queues=[];
  for(const role of ['client','relay']){
   const scope=join(root,name+'-'+role);
   execFileSync(vault,['--windows-scattering-create-lab',scope],{windowsHide:true,timeout:15000});
   const queueDir=join(scope,'queue');queues.push(queueDir);
   const ep=await startScatteringMailboxEndpoint({...shared,role,queueDir,stateDir:join(scope,'state'),httpPort:role==='client'?0:relayPort},{windowsBootstrap:{binary:vault,binarySha256:pin,dir:scope}});
   pair.push(ep);endpoints.push(ep);
  }
  const ports=[await freeUDP(),await freeUDP()];assert.notEqual(ports[0],ports[1]);
  function launch(args){const p=spawn(pacer,args,{stdio:'ignore',windowsHide:true});p.on('error',()=>{});kids.push(p);return p;}
  for(let i=0;i<2;i++){
   launch(['-mode','sink','-listen','127.0.0.1:'+ports[i],'-forward','127.0.0.1:'+pair[i].recvPort]);
   launch(['-target','127.0.0.1:'+ports[1-i],'-queue-dir',queues[i],'-period-us','5000','-poll','10ms','-wait-mode','native']);
  }
  return 'http://127.0.0.1:'+pair[0].httpPort+'/';
 }
 const payload={subject:'Synthetic Windows PQ roundtrip',body:'QS-E2E '+randomBytes(32).toString('hex')};
 try{
  restoreNativeMailbox([]);
  peers=invoke('init');assert.equal(peers.length,2);assert.notEqual(peers[0].deviceId,peers[1].deviceId);
  tokens=peers.map(()=>randomBytes(32).toString('hex'));
  relayPort=await startRelay();
  const endpointA=await transport('alice'),endpointB=await transport('bob');
  await pause(600);assert.ok(kids.every(p=>p.exitCode===null));
  const boots=peers.map((p,i)=>({binary:vault,binarySha256:pin,dir:join(root,i===0?'alice':'bob')}));
  const config=peers.map((p,i)=>({windowsLab:{dir:boots[i].dir},pqMode:{enabled:true,address:p.address,deviceId:p.deviceId},
   windowsScattering:{enabled:true,address:p.address,deviceId:p.deviceId,token:tokens[i],endpoint:i===0?endpointA:endpointB,receiptKeyFile:join(boots[i].dir,'receipt.key')}}));
  const a=await createWindowsNativeStorage(boots[0]),b=await createWindowsNativeStorage(boots[1]);
  const contactBytes=await a.read(join(boots[0].dir,'contacts.json'));
  const contacts=JSON.parse(contactBytes.toString('utf8'));contactBytes.fill(0);
  const draft=await saveWindowsDraft(config[0],contacts,a,{to:peers[1].address,...payload});
  const input=join(boots[0].dir,draft.file),output=join(boots[0].dir,draft.file.replace(/^draft-/,'wire-'));
  const rawDraft=await readFile(input);assert.ok(rawDraft.subarray(0,5).equals(Buffer.from([81,83,68,50,0])));assert.ok(!rawDraft.includes(Buffer.from(payload.body)));
  let signed;
  const sent=await composeAndSendWindowsLab(config[0],a,{input,output,approve:async()=>true,
   connect:async()=>({sealHybrid:async(context,p)=>{assert.deepEqual(p,payload);signed=invoke('seal','',draft.file);assert.deepEqual(signed.context,context);return signed;},close(){}})});
  assert.equal(sent.status,'deposited');assert.equal(sent.relayStatus,'queued');
  assert.equal(sent.digest,nativeRecordDigest(signed));assert.ok(!JSON.stringify(signed).includes(payload.body));
  assert.equal(nativeMailboxEntries().length,1);
  // Deliberate corrupted signature must be refused by an independent reopened receiver.
  const tamper=structuredClone(signed);const sig=Buffer.from(tamper.senderAuth.pqSignature,'base64url');sig[0]^=1;tamper.senderAuth.pqSignature=sig.toString('base64url');
  assert.throws(()=>invoke('open',JSON.stringify(tamper)));
  const receiptPath=join(boots[1].dir,'receipt-roundtrip.json');
  // Actual relay endpoint refuses the first ACK, AFTER a durable receipt was
  // written and read back by the real Windows receiving client.
  await assert.rejects(runWindowsScatteringMail(config[1],b,{operation:'receive',path:receiptPath,approve:async()=>true,
   connect:async()=>({openHybrid:async w=>invoke('open',JSON.stringify(w)),close(){}})}));
  assert.equal(acks,0);assert.equal(nativeMailboxEntries()[0].acknowledgedAt,null);
  const receiptRaw=await readFile(receiptPath);assert.ok(!receiptRaw.includes(Buffer.from(payload.body)));
  const receiptKey=await b.read(config[1].windowsScattering.receiptKeyFile);
  try{const receipt=openReceipt(receiptKey,config[1].windowsScattering,JSON.parse(receiptRaw.toString()));assert.deepEqual(receipt.payload,payload);assert.equal(receipt.digest,sent.digest);}finally{receiptKey.fill(0);}
  // Relay service is stopped, the in-memory mailbox discarded, and the
  // persisted snapshot loaded into a fresh server. No receiver private key
  // or plaintext is needed for the authenticated receipt recovery.
  await stopRelay();restoreNativeMailbox([]);const persisted=await readFile(snapshot,'utf8');
  assert.ok(!persisted.includes(payload.body));restoreNativeMailbox(JSON.parse(persisted));
  assert.equal(nativeMailboxEntries()[0].acknowledgedAt,null);
  await startRelay(relayPort);
  const reopened=await createWindowsNativeStorage(boots[1]);
  const result=await runWindowsScatteringMail(config[1],reopened,{operation:'confirm-receipt',path:receiptPath,approve:async()=>true,connect:async()=>{throw Error('must not reopen or resign mail to ACK');}});
  assert.equal(result.status,'acknowledged');assert.equal(result.digest,sent.digest);assert.equal(acks,1);
  assert.equal((await runWindowsScatteringMail(config[1],reopened,{operation:'receive',path:join(boots[1].dir,'receipt-empty.json'),approve:async()=>true,connect:async()=>{throw Error('acknowledged mail must not be redelivered');}})).status,'empty');
  assert.ok(nativeMailboxEntries()[0].acknowledgedAt!==null);
  assert.ok(processes>=3);assert.ok(relayRequests>=6);
  console.log('QS_MAIL_E2E_PASS: actual Windows PQ vault reopen, DPAPI draft, separate UDP carriers, receiver decryption, encrypted receipt, relay snapshot restart, recovered ACK. Synthetic trust only; no physical host or production authorization.');
 }finally{
  for(const ep of endpoints)ep.close();
  const exits=kids.map(p=>p.exitCode!==null||p.signalCode!==null?Promise.resolve():new Promise(r=>{p.once('close',r);p.once('error',r);}));
  for(const p of kids)p.kill();await Promise.all(exits);
  await stopRelay();restoreNativeMailbox([]);await rm(root,{recursive:true,force:true,maxRetries:10,retryDelay:200});
 }
});
