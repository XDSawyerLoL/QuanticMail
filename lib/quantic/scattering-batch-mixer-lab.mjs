// Laboratory batching ONLY: randomized order is not a proven anonymous mix.
// The outgoing native Go pacer remains fixed-rate, including when idle.
import {randomInt} from 'node:crypto';

const check=(ok,why)=>{if(!ok)throw Error(why)};
export function createScatteringBatchMixer({batchSize=40,onBatch,draw=randomInt}){
 check(Number.isSafeInteger(batchSize)&&batchSize>=2&&batchSize<=128&&
   typeof onBatch==='function'&&typeof draw==='function','invalid mixer configuration');
 const pending=[];
 let emitted=0,completed=0;
 function release(n){
  const batch=pending.slice(0,n);
  // Fisher-Yates, with crypto.randomInt by default. Injection only for unit tests.
  for(let i=batch.length-1;i>0;i--){
   const j=draw(i+1);
   check(Number.isSafeInteger(j)&&j>=0&&j<=i,'invalid shuffle randomness');
   [batch[i],batch[j]]=[batch[j],batch[i]];
  }
  onBatch(batch); // synchronous callback must either commit the entire batch or fail
  pending.splice(0,n);emitted+=n;completed++;
  return n;
 }
 return {
  add(item){
   check(item&&Buffer.isBuffer(item.packet)&&item.packet.length===168&&
      (item.source===0||item.source===1),'invalid synthetic input');
   check(pending.length<batchSize,'batch backpressure failed');
   pending.push({packet:Buffer.from(item.packet),source:item.source});
   if(pending.length===batchSize)release(batchSize);
  },
  drain(){if(pending.length)return release(pending.length);return 0;},
  stats(){return {batchSize,pending:pending.length,emitted,batches:completed};},
 };
}
