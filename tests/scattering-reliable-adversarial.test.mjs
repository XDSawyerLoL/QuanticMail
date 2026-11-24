import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {reliableCellStream,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';

// No physical network. Deterministic hostile delivery of the existing RC2
// reliable stream's real AES-GCM frames. No new production protocol or keys.
function pair() {
  const ab=randomBytes(32),ba=randomBytes(32);
  const wireAB=[],wireBA=[];
  let now=0;
  const a=reliableCellStream({sendKey:ab,recvKey:ba,autoTick:false,compactPacing:true,
    clock:()=>now,publish:frames=>{wireAB.push(frames);return true;}});
  const b=reliableCellStream({sendKey:ba,recvKey:ab,autoTick:false,compactPacing:true,
    clock:()=>now,publish:frames=>{wireBA.push(frames);return true;}});
  const errors=[];
  a.stream.on('error',e=>errors.push(e));
  b.stream.on('error',e=>errors.push(e));
  return {a,b,ab,ba,wireAB,wireBA,errors,
    step(t){now=t;a.tick();b.tick();},
    close(){a.stream.destroy();b.stream.destroy();ab.fill(0);ba.fill(0);}};
}
test('drops, duplicates, reordering, corruption and missing ACKs recover without changing fixed cadence',async()=>{
  const x=pair(), message=randomBytes(1024),received=[];
  let writeDone=false,writeError=null;
  x.b.stream.on('data',buf=>received.push(buf));
  const firstDropped=new Set();
  let injected=false,ackDropped=false;
  try {
    x.a.stream.write(message,error=>{writeDone=true;writeError=error;});
    for(let n=0;n<55 && !writeDone;n++){
      x.step(n*50);
      const fromA=x.wireAB.at(-1);
      assert.equal(fromA.length,2);
      assert.ok(fromA.every(frame=>frame.length===168));
      // Reverse in-slot order and lose the first occurrence of seq 0 and 2.
      for(const frame of [...fromA].reverse()){
        const opened=openReliable(x.ab,frame);
        if(opened?.seq!==null && opened?.seq!==undefined &&
           [0,2].includes(opened.seq) && !firstDropped.has(opened.seq)){
          firstDropped.add(opened.seq);continue;
        }
        if(!injected && opened?.seq!==null && opened?.seq!==undefined){
          const corrupt=Buffer.from(frame);corrupt[40]^=1;
          x.b.receive(corrupt);injected=true;
        }
        x.b.receive(frame);
        if(opened?.seq!==null && opened?.seq!==undefined && opened.seq===3)
          x.b.receive(frame); // replayed authenticated duplicate
      }
      // Lose the first ACK-bearing reverse tick. A subsequent fixed tick
      // must acknowledge without creating a traffic-triggered extra packet.
      const fromB=x.wireBA.at(-1);
      assert.equal(fromB.length,2);
      if(!ackDropped){ackDropped=true;} else for(const frame of fromB)x.a.receive(frame);
      await new Promise(setImmediate);
    }
    await new Promise(setImmediate);
    assert.ok(writeError==null);
    assert.equal(writeDone,true);
    assert.deepEqual(Buffer.concat(received),message);
    assert.deepEqual([...firstDropped].sort((a,b)=>a-b),[0,2]);
    assert.ok(x.a.stats.retransmitted>=2,'lost frames must be retransmitted');
    assert.ok(x.b.stats.duplicates>=1);
    assert.ok(x.b.stats.coverOrInvalid>=1);
    assert.equal(x.errors.length,0);
    assert.ok(x.wireAB.every(batch=>batch.length===2 && batch.every(frame=>frame.length===168)));
    assert.ok(x.wireBA.every(batch=>batch.length===2 && batch.every(frame=>frame.length===168)));
  } finally {x.close();}
});
test('permanent ACK blackout fails closed within write deadline; no successful delivery claim',async()=>{
  const x=pair();let callbackError=null,completed=false;
  try{
    x.a.stream.write(Buffer.alloc(256,0x42),e=>{completed=true;callbackError=e;});
    for(let n=0;n<70;n++){
      x.step(n*50);
      // Deliberately discard all forward and backward frames.
      if(x.a.stream.destroyed)break;
    }
    await new Promise(setImmediate);
    assert.equal(x.a.stream.destroyed,true);
    assert.ok(completed);
    assert.ok(callbackError instanceof Error);
    assert.match(callbackError.message,/deadline/i);
    assert.ok(x.errors.some(e=>/deadline/i.test(e.message)));
  }finally{x.close();}
});
test('a forged ACK outside the advertised send window is rejected',async()=>{
  const x=pair();
  try{
    const forged=await import('../labs/quantic-native/scattering/scattering-reliable-lab.mjs');
    x.step(0);
    x.a.receive(forged.sealReliable(x.ba,{ack:8192}));
    await new Promise(setImmediate);
    assert.equal(x.a.stream.destroyed,true);
    assert.ok(x.errors.some(e=>/ack for unsent sequence/.test(e.message)));
  }finally{x.close();}
});
