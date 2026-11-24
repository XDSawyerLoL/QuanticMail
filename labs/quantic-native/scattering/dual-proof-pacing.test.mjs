import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {reliableCellStream} from './scattering-reliable-lab.mjs';
test('dual proof feed uses fixed four-cell batches, idle and busy',async()=>{
  const sendKey=randomBytes(32),recvKey=randomBytes(32);let now=0;const batches=[];
  const a=reliableCellStream({sendKey,recvKey,autoTick:false,clock:()=>now,publish:p=>{batches.push(p);return true},compactPacing:true,dualProofPacing:true});
  const b=reliableCellStream({sendKey:recvKey,recvKey:sendKey,autoTick:false,clock:()=>now,publish:p=>{for(const cell of p)a.receive(cell);return true},compactPacing:true,dualProofPacing:true});
  const chunks=[];b.stream.on('data',c=>chunks.push(c));a.tick();assert.equal(batches[0].length,4);
  const data=randomBytes(8192);let complete=false;let error;
  a.stream.write(data,e=>{error=e;complete=true;});
  for(let i=1;i<=40;i++){now=i*25;a.tick();for(const c of batches.at(-1))b.receive(c);b.tick();await new Promise(resolve=>setImmediate(resolve));}
  assert.ok(error==null);assert.equal(complete,true);assert.deepEqual(Buffer.concat(chunks),data);
  assert.ok(batches.every(p=>p.length===4&&p.every(c=>c.length===168)));
  a.stream.destroy();b.stream.destroy();
});
test('dual proof pacing without persistent feed is refused',()=>{
 assert.throws(()=>reliableCellStream({sendKey:randomBytes(32),recvKey:randomBytes(32),autoTick:false,dualProofPacing:true}));
});
