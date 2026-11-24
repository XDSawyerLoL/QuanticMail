// Two independently scoped local clients, each on its own real native UDP
// Scattering pacer/sink pair. Windows GUI adapters are exercised with
// synthetic vaults: this is NOT a real PQ broker or physical two-host proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {generateKeyPairSync,randomBytes,randomUUID} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,win32} from 'node:path';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
import {composeAndSendWindowsLab} from '../desktop/native-windows-integrated-mail.mjs';
import {receiveWindowsLabFromGUI} from '../desktop/native-windows-gui-receive.mjs';
import {
 restoreNativeMailbox,normalizeNativeRecord,nativeRecordDigest,
 enqueueNativeRecord,pullNativeRecord,acknowledgeNativeRecord,recoverNativeRecord
} from '../lib/quantic/native-mailbox.mjs';
import {openReceipt} from '../desktop/native-receipt-store.mjs';

const binary=process.env.QUANTIC_SCATTERING_NATIVE_TEST
 ?resolve(process.env.QUANTIC_SCATTERING_NATIVE_TEST):null;
const prefix='/api/quantic/native/v1/';
const p1='alice~'+'a'.repeat(32)+'@quantic';
const p2='bobby~'+'b'.repeat(32)+'@quantic';
const d1='d-'+'1'.repeat(32),d2='d-'+'2'.repeat(32);
const tokens={[p1]:'alice-'+('a'.repeat(56)),[p2]:'bobby-'+('b'.repeat(56))};
const {publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=publicKey.export({format:'jwk'});
const base=()=>({
 cryptoSuite:'QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1',
 keyMode:'hybrid-static-fallback',
 classicalEphemeralPublicKey:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y},
 pqKemCiphertext:randomBytes(1088).toString('base64url'),
 iv:randomBytes(12).toString('base64url'),
 ciphertext:randomBytes(48).toString('base64url')
});
function syntheticWire(context){
 return normalizeNativeRecord({
  format:'quantic-native-mail',version:1,context,
  envelope:base(),
  senderAuth:{classicalSignature:randomBytes(64).toString('base64url'),
   pqSignature:randomBytes(3309).toString('base64url')}
 });
}
function newActor(address,deviceId,dir,url,messages){
 const key=randomBytes(32);
 const cfg={windowsLab:{dir},pqMode:{enabled:true,address,deviceId},
  windowsScattering:{enabled:true,address,deviceId,endpoint:url,
   token:tokens[address],receiptKeyFile:win32.join(dir,'receipt.key')}};
 const files=new Map();
 let writes=0,opened=0;
 const storage={
  async read(path){
   if(path===cfg.windowsScattering.receiptKeyFile)return Buffer.from(key);
   if(!files.has(path))throw Error('Unknown private native file');
   return Buffer.from(files.get(path));
  },
  async writeDraft(path,b){
   assert.equal(files.has(path),false);files.set(path,Buffer.from(b));
  },
  async writeWire(path,b){
   assert.equal(files.has(path),false);files.set(path,Buffer.from(b));writes++;
  },
  async writeReceipt(path,b){
   assert.equal(files.has(path),false);files.set(path,Buffer.from(b));writes++;
  }
 };
 const connect=async()=>({
  async sealHybrid(context,payload){
   const record=syntheticWire(context);
   messages.set(nativeRecordDigest(record),structuredClone(payload));
   return record;
  },
  async openHybrid(record){
   opened++;
   const value=messages.get(nativeRecordDigest(record));
   if(!value)throw Error('Synthetic broker refused unknown record');
   return structuredClone(value);
  },
  close(){}
 });
 const seal=async(to,toDeviceId,subject,body)=>{
  const id=randomUUID();
  const context={clientMessageId:'qs-'+id,from:address,fromDeviceId:deviceId,to,toDeviceId};
  const draft=win32.join(dir,'draft-'+id.replaceAll('-','')+'.json');
  const wire=win32.join(dir,'wire-'+randomUUID().replaceAll('-','')+'.json');
  files.set(draft,Buffer.from(JSON.stringify({context,payload:{subject,body}})));
  let approvals=0;
  const result=await composeAndSendWindowsLab(cfg,storage,{input:draft,output:wire,
   connect,approve:async()=>{approvals++;return approvals<=2;}});
  assert.equal(approvals,2);
  assert.equal(result.status,'deposited');
  assert.equal(result.relayStatus,'queued');
  assert.equal(result.legacyDeletionAuthorized,false);
  assert.ok(files.has(wire));
  return result;
 };
 const receive=async(approve=async()=>true)=>{
  const r=await receiveWindowsLabFromGUI(cfg,storage,{approve,connect});
  assert.equal(r.remoteDeliveryVerified,false);
  return r;
 };
 return {cfg,storage,files,seal,receive,stats:()=>({writes,opened})};
}
test('two isolated GUI clients exchange synthetic encrypted envelopes across two real native UDP links; receipt persists before ACK',
 {skip:process.platform!=='linux'||!binary,timeout:180000},async()=>{
  restoreNativeMailbox([]);
  const root=await mkdtemp(join(tmpdir(),'qs-gui-udp-e2e-'));
  const links=[];
  const messages=new Map();
  let operations=0,acks=0;
  const server=createServer(async(req,res)=>{
   const respond=(status,value)=>{
    const b=Buffer.from(JSON.stringify(value));
    res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store'});
    res.end(b);
   };
   try{
    if(req.method!=='POST'||!req.url?.startsWith(prefix))throw Error('Bad route');
    const op=req.url.slice(prefix.length);
    if(!['send','pull','ack','recover'].includes(op))throw Error('Invalid mailbox operation');
    const chunks=[];let size=0;
    for await(const c of req){size+=c.length;if(size>32768)throw Error('Oversize');chunks.push(c);}
    const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const who=op==='send'?body.context?.from:body.address;
    if(req.headers.authorization!=='Bearer '+tokens[who])throw Error('Untrusted actor');
    operations++;
    if(op==='send'){
     const row=enqueueNativeRecord(normalizeNativeRecord(body));
     respond(202,row);return;
    }
    if(op==='pull'){
     respond(200,{item:pullNativeRecord(who,body.deviceId)});return;
    }
    if(op==='ack'){
     acks++;respond(200,acknowledgeNativeRecord(who,body.deviceId,body.id,body.digest));return;
    }
    respond(200,{item:recoverNativeRecord(who,body.deviceId,body.id,body.digest)});
   }catch{respond(409,{error:'synthetic mailbox request refused'});}
  });
  try{
   await new Promise((r,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',r);});
   const relayPort=server.address().port;
   links.push(await startNativeScatteringLink({dir:join(root,'link-a'),binary,relayPort}));
   links.push(await startNativeScatteringLink({dir:join(root,'link-b'),binary,relayPort}));
   assert.notEqual(links[0].epochId,links[1].epochId,'isolated carrier epochs');
   const a=newActor(p1,d1,'C:\\QuanticLab\\Alice',links[0].url,messages);
   const b=newActor(p2,d2,'C:\\QuanticLab\\Bobby',links[1].url,messages);
   assert.notEqual(a.cfg.windowsScattering.token,b.cfg.windowsScattering.token);
   await a.seal(p2,d2,'Forward lab','Alice to Bob only');
   let approved=false;
   const cancelled=await b.receive(async()=>{approved=true;return false;});
   assert.equal(approved,true);
   assert.equal(cancelled.status,'cancelled');
   assert.equal(pullNativeRecord(p2,d2)?.acknowledgedAt,null,'cancel cannot ACK');
   const gotB=await b.receive();
   assert.equal(gotB.status,'opened-and-acknowledged-on-local-relay');
   assert.match(gotB.display,/Alice to Bob only/);
   assert.equal(pullNativeRecord(p2,d2),null);
   assert.equal(acks,1,'ACK only after durable receipt');
   assert.equal([...b.files.keys()].filter(x=>win32.basename(x).startsWith('receipt-')).length,1);
   const receiptPath=[...b.files.keys()].find(x=>win32.basename(x).startsWith('receipt-'));
   const stored=JSON.parse(b.files.get(receiptPath));
   assert.equal(JSON.stringify(stored).includes('Alice to Bob only'),false,'encrypted receipt contains no plaintext');
   const recovered=openReceipt(await b.storage.read(b.cfg.windowsScattering.receiptKeyFile),b.cfg.windowsScattering,stored);
   assert.equal(recovered.payload.body,'Alice to Bob only');

   await b.seal(p1,d1,'Reply lab','Bob to Alice only');
   const gotA=await a.receive();
   assert.equal(gotA.status,'opened-and-acknowledged-on-local-relay');
   assert.match(gotA.display,/Bob to Alice only/);
   assert.equal(pullNativeRecord(p1,d1),null);
   assert.equal(acks,2);
   assert.equal(a.stats().opened,1);
   assert.equal(b.stats().opened,1);
   assert.ok(operations>=8,'both client routes traversed independently');
   assert.equal(server.address().address,'127.0.0.1','no public HTTP listener');
  }finally{
   for(const link of links.reverse())await link.close();
   server.closeAllConnections();
   if(server.listening)await new Promise(r=>server.close(r));
   restoreNativeMailbox([]);
   await rm(root,{recursive:true,force:true,maxRetries:10,retryDelay:100});
  }
 });
