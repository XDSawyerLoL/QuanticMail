import test from 'node:test';
import assert from 'node:assert/strict';
import {createSocket} from 'node:dgram';
import {startTwoHostReceiver,runTwoHostSender} from '../desktop/native-two-host-network-lab.mjs';

async function randomLocalPort(){
 const s=createSocket('udp4');
 await new Promise((resolve,reject)=>{s.once('error',reject);s.bind(0,'127.0.0.1',resolve);});
 const port=s.address().port;
 await new Promise(resolve=>s.close(resolve));
 return port;
}
test('Real UDP loopback challenge/response is authenticated both ways, not remote mail',async()=>{
 const port=await randomLocalPort();
 const r=await startTwoHostReceiver({port,listen:'127.0.0.1',seconds:8});
 try{
  assert.match(r.code,/^[a-f0-9]{24}$/);
  const s=await runTwoHostSender({host:'127.0.0.1',port,code:r.code,seconds:5});
  const received=await r.wait;
  assert.equal(s.status,'synthetic-udp-mutual-proof');
  assert.equal(received.status,'synthetic-udp-acknowledged');
  assert.equal(s.cryptographicMailDelivered,false);
  assert.equal(s.distinctPhysicalComputersVerified,false);
  assert.equal(received.anonymousTransportVerified,false);
 }finally{r.cancel();}
});
test('Malformed pairing code is rejected before any UDP proof',async()=>{
 await assert.rejects(runTwoHostSender({host:'127.0.0.1',port:49001,code:'invalid-code',seconds:5}));
 await assert.rejects(runTwoHostSender({host:'0.0.0.0',port:49001,code:'a'.repeat(24),seconds:5}));
});
test('Different valid secret cannot authenticate a synthetic UDP packet',async()=>{
 const port=await randomLocalPort();
 const r=await startTwoHostReceiver({port,listen:'127.0.0.1',seconds:5});
 // Attach the rejection assertion immediately: receiver and sender may
 // time out in the same event-loop turn, before a later await.
 const rejectedReceiver=assert.rejects(r.wait,/No authenticated synthetic UDP exchange/);
 try{
  await assert.rejects(runTwoHostSender({host:'127.0.0.1',port,code:'0'.repeat(24)===r.code?'1'.repeat(24):'0'.repeat(24),seconds:5}));
  await rejectedReceiver;
 }finally{r.cancel();}
});
