import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createCommitteeSession} from '../lib/quantic/pay-committee-session.mjs';
const network='a'.repeat(64),authorityPin='b'.repeat(64);
test('fresh epoch per operation, duplicate epoch refused before transmission, ambiguity halts without retry',async()=>{
 let hits=0,closes=0,issued=0,fail=false,reuse=false;
 const server=createServer((req,res)=>{hits++;req.resume();req.on('end',()=>{
  if(fail){req.socket.destroy();return;}
  res.writeHead(200,{'Content-Type':'application/json'});
  res.end(JSON.stringify({scope:network,simulationOnly:true,realPaymentAuthorized:false,output:null}));
 });});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const provision=async p=>({network,authorityPin,profile:p.profile,epochId:(reuse?1:++issued).toString(16).padStart(64,'0'),loopbackPort:server.address().port,token:'c'.repeat(64),close:async()=>{closes++;}});
 try{
  const a=createCommitteeSession({network,authorityPin,provision,maxEpochs:4});
  await a.status();await a.prepare({scope:network,input:{round:0,value:'d'.repeat(64)}});
  assert.equal(hits,2);assert.equal(closes,2);assert.equal(a.sessionStatus().epochsConsumed,2);
  reuse=true;await assert.rejects(a.status(),/reconciliation/);assert.equal(hits,2);assert.equal(closes,3);
  await assert.rejects(a.status());assert.equal(a.sessionStatus().halted,true);
  reuse=false;fail=true;
  const b=createCommitteeSession({network,authorityPin,provision});
  await assert.rejects(b.prepare({scope:network,input:{round:0,value:'d'.repeat(64)}}),/reconciliation/);
  assert.equal(hits,3);assert.equal(b.sessionStatus().epochsStarted,1);
  await assert.rejects(b.prepare({}));assert.equal(hits,3);
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
