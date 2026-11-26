import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
test('replica client preflights bounded epoch and does not transmit beyond sixteen calls',async()=>{
 const network='a'.repeat(64);let hits=0;
 const server=createServer((req,res)=>{hits++;req.resume();req.on('end',()=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({scope:network,simulationOnly:true,realPaymentAuthorized:false,output:null}));});});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const client=createPayReplicaCarrier({loopbackPort:server.address().port,token:'b'.repeat(64),network});
  for(let i=0;i<15;i++)await client.status();
  assert.equal(client.remainingOperations(),1);
  await assert.rejects(client.learn({large:'x'.repeat(40000)}),/epoch budget/);
  assert.equal(hits,15);
  await client.status();
  await assert.rejects(client.status(),/epoch budget/);
  assert.equal(hits,16);
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
