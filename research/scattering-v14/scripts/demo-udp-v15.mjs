/** Local-only UDP proof of pinned Ed25519 / X25519 handshake and restart replay protection. */
import dgram from 'node:dgram';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {FrameSender,FrameReceiver,MessageCollector,fragmentMessage} from '../src/transport.mjs';
import {initiateSession,respondSession,finishInitiatorSession,finishResponderSession} from '../src/session-v15.mjs';
import {DurableFrameReceiver} from '../src/durable-replay-v15.mjs';

const MAGIC='QS-SCATTERING-V15-UDP-LAB';
function toJSON(type,fields){
 const b={protocol:MAGIC,type};for(const [k,v] of Object.entries(fields))b[k]=v.toString('base64');
 return Buffer.from(JSON.stringify(b));
}
function decode(buf,type,shape){
 if(buf.length>2048)throw Error('Oversized handshake packet');
 const obj=JSON.parse(buf.toString());
 if(obj.protocol!==MAGIC||obj.type!==type)throw Error('Wrong handshake stage');
 const o={};for(const [k,n] of Object.entries(shape)){
  if(typeof obj[k]!=='string'||!/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(obj[k]))throw Error(`Invalid field ${k}`);
  o[k]=Buffer.from(obj[k],'base64');
  if(o[k].length!==n||o[k].toString('base64')!==obj[k])throw Error(`Wrong field size ${k}`);
 }
 return o;
}
function inbox(socket){
 const queued=[],waiting=[];
 socket.on('message',(packet,info)=>{
  const entry={packet,info};const waiter=waiting.shift();
  if(waiter){clearTimeout(waiter.timer);waiter.resolve(entry);}else queued.push(entry);
 });
 return async()=>{
  if(queued.length)return queued.shift();
  return new Promise((resolve,reject)=>{
   const waiter={resolve,timer:null};
   waiter.timer=setTimeout(()=>{const i=waiting.indexOf(waiter);if(i>=0)waiting.splice(i,1);reject(new Error('UDP loopback timeout'));},4000);
   waiting.push(waiter);
  });
 };
}
const bind=socket=>new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(0,'127.0.0.1',resolve);});
const send=(socket,buf,port)=>new Promise((resolve,reject)=>socket.send(buf,port,'127.0.0.1',e=>e?reject(e):resolve()));
export async function runDemo(){
 const alice=dgram.createSocket('udp4'),bob=dgram.createSocket('udp4');
 const tmp=await mkdtemp(join(tmpdir(),'quantic-v15-udp-'));
 let durable;
 try{
  await Promise.all([bind(alice),bind(bob)]);
  const inboxA=inbox(alice),inboxB=inbox(bob);
  const aKeys=generateKeyPairSync('ed25519'),bKeys=generateKeyPairSync('ed25519');
  const {handle:i,hello}=initiateSession({localSigningPrivateKey:aKeys.privateKey,peerSigningPublicKey:bKeys.publicKey});
  await send(alice,toJSON('hello',hello),bob.address().port);
  const receivedHello=decode((await inboxB()).packet,'hello',{nonce:32,ephemeralPublicKey:44,signature:64});
  const {handle:r,response}=respondSession({localSigningPrivateKey:bKeys.privateKey,peerSigningPublicKey:aKeys.publicKey,hello:receivedHello});
  await send(bob,toJSON('response',response),alice.address().port);
  const receivedResponse=decode((await inboxA()).packet,'response',{nonce:32,ephemeralPublicKey:44,signature:64});
  const {session:a,finish}=finishInitiatorSession(i,receivedResponse);
  await send(alice,toJSON('finish',finish),bob.address().port);
  const receivedFinish=decode((await inboxB()).packet,'finish',{confirmation:32});
  const b=finishResponderSession(r,receivedFinish);
  const ready=new FrameSender({masterSecret:b.sendMasterSecret,sessionId:b.sessionId}).nextCover();
  await send(bob,ready,alice.address().port);
  const receivedReady=(await inboxA()).packet;
  assert.equal(new FrameReceiver({masterSecret:a.receiveMasterSecret,sessionId:a.sessionId}).accept(receivedReady).ok,true);
  durable=await DurableFrameReceiver.create({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:join(tmp,'replay.json')});
  const sender=new FrameSender({masterSecret:a.sendMasterSecret,sessionId:a.sessionId});
  const message=Buffer.from('real UDP loopback with pinned signing identities, fresh keys and persistent replay state');
  const packets=fragmentMessage(message).slice(0,8).map(shard=>sender.nextShard(shard));
  const collector=new MessageCollector();let delivered;
  for(const pkt of packets){
   await send(alice,pkt,bob.address().port);
   const received=(await inboxB()).packet;
   assert.equal(received.length,168);
   const result=await durable.accept(received);
   assert.equal(result.ok,true);
   delivered=collector.add(result.shard)?.message??delivered;
  }
  assert.deepEqual(delivered,message);
  await durable.close();durable=null;
  const reopened=await DurableFrameReceiver.resume({masterSecret:b.receiveMasterSecret,sessionId:b.sessionId,stateFile:join(tmp,'replay.json')});
  const replay=await reopened.accept(packets[0]);
  assert.equal(replay.error,'replayed_or_stale');
  await reopened.close();
  return {lab:'v15',transport:'real UDP 127.0.0.1',sessionAuthenticated:true,pinnedIdentity:'Ed25519',ephemeralKeyAgreement:'X25519',postQuantum:false,
   delivered:delivered.toString(),shards:packets.length,frameBytes:168,replayAfterRestart:replay.error,
   productionReady:false};
 }finally{if(durable)await durable.close();alice.close();bob.close();await rm(tmp,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url.endsWith('/'+process.argv[1].replaceAll('\\','/').split('/').pop())){
 runDemo().then(result=>console.log(JSON.stringify(result,null,2))).catch(e=>{console.error(e);process.exitCode=1;});
}