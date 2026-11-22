// Capacity accounting only. No implementation of sharding, batching, or anonymity.
// All rates are decimal and exclude IP/UDP/link overhead, packet loss and application framing.
import test from 'node:test';
import assert from 'node:assert/strict';
const SECOND_PER_DAY=86400;
function budget({periodMs,preparedPerSecond,links,proofBytes,transactionsPerProof=1,utilization=.5}){
 for(const n of [periodMs,preparedPerSecond,links,proofBytes,transactionsPerProof])assert.ok(Number.isSafeInteger(n)&&n>0);
 assert.ok(utilization>0&&utilization<=1);
 const packetsPerSecond=1000/periodMs;
 assert.ok(preparedPerSecond<=packetsPerSecond);
 const usefulBytesPerDirection=preparedPerSecond*128;
 return {links,packetsPerSecond,coverBytesPerSecond:links*2*packetsPerSecond*168,coverBytesPerDay:links*2*packetsPerSecond*168*SECOND_PER_DAY,idealProofSeconds:Math.ceil(proofBytes/128)/preparedPerSecond,idealTransactionsPerSecondPerLink:usefulBytesPerDirection*transactionsPerProof/proofBytes,planningTransactionsPerSecondPerLink:usefulBytesPerDirection*transactionsPerProof/proofBytes*utilization};
}
test('accounting for currently configured native voting links and measured JSON proofs',t=>{
 const x=budget({periodMs:5,preparedPerSecond:160,links:16,proofBytes:211993});
 assert.equal(x.coverBytesPerSecond,1075200);
 assert.equal(x.coverBytesPerDay,92897280000);
 assert.ok(x.idealProofSeconds>10);
 t.diagnostic(JSON.stringify(x));
});
test('one permanent bidirectional link per user does not scale economically without new design',t=>{
 for(const links of [1,1000000,1000000000]){
  const x=budget({periodMs:20,preparedPerSecond:40,links,proofBytes:211993});
  assert.equal(x.coverBytesPerSecond,links*16800);
  t.diagnostic(JSON.stringify({links,coverBytesPerSecond:x.coverBytesPerSecond,coverBytesPerDay:x.coverBytesPerDay}));
 }
});
test('ideal proof transmission lower bound and hypothetical batching parameter',t=>{
 for(const proofBytes of [51651,37878,211993])for(const transactionsPerProof of [1,100,1000]){
  const x=budget({periodMs:5,preparedPerSecond:160,links:16,proofBytes,transactionsPerProof});
  t.diagnostic(JSON.stringify({proofBytes,transactionsPerProof,idealProofSeconds:x.idealProofSeconds,planningTransactionsPerSecondPerLink:x.planningTransactionsPerSecondPerLink}));
 }
 assert.throws(()=>budget({periodMs:20,preparedPerSecond:160,links:16,proofBytes:1}));
});
