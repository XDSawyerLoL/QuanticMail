import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealNestedLab} from '../lib/quantic/scattering-e2e-envelope-lab.mjs';
import {resealLabHop} from '../lib/quantic/scattering-hop-reseal-lab.mjs';
import {evaluateTimeOnlyLab,timeOnlyNearestIngress} from '../lib/quantic/scattering-temporal-correlation-lab.mjs';
function pcap(rows) {
 const global=Buffer.alloc(24);global.writeUInt32LE(0xa1b2c3d4,0);
 global.writeUInt16LE(2,4);global.writeUInt16LE(4,6);
 global.writeUInt32LE(65535,16);global.writeUInt32LE(1,20);
 const records=rows.map(([ms,packet])=>{
  const eth=Buffer.alloc(14),ip=Buffer.alloc(20),udp=Buffer.alloc(8);
  eth.writeUInt16BE(0x0800,12);ip[0]=0x45;ip[9]=17;
  ip.writeUInt16BE(196,2);
  udp.writeUInt16BE(40001,0);udp.writeUInt16BE(49003,2);
  udp.writeUInt16BE(176,4);
  const frame=Buffer.concat([eth,ip,udp,packet]);const h=Buffer.alloc(16);
  h.writeUInt32LE(1763982000,0);h.writeUInt32LE(Math.round(ms*1000),4);
  h.writeUInt32LE(frame.length,8);h.writeUInt32LE(frame.length,12);
  return Buffer.concat([h,frame]);
 });
 return Buffer.concat([global,...records]);
}
test('the time-only classifier receives timestamps, never keys or source IDs',()=>{
 assert.equal(timeOnlyNearestIngress({sourceATimes:[100],sourceBTimes:[110],egressTime:120}), 'B');
 assert.equal(timeOnlyNearestIngress({sourceATimes:[100],sourceBTimes:[110],egressTime:101}), 'A');
 assert.equal(timeOnlyNearestIngress({sourceATimes:[100],sourceBTimes:[110],egressTime:500,maxLagMs:250}),null);
 assert.throws(()=>timeOnlyNearestIngress({sourceATimes:[NaN],sourceBTimes:[110],egressTime:120}));
});
test('offline scoring uses E2E labels exclusively for grading with cover false-positives reported',()=>{
 const ingressA=randomBytes(32),ingressB=randomBytes(32),
   outputKey=randomBytes(32),e2e=randomBytes(32);
 try{
  const aa=sealNestedLab({hopKey:ingressA,endToEndKey:e2e,senderId:0,seq:0,data:randomBytes(59)});
  const bb=sealNestedLab({hopKey:ingressB,endToEndKey:e2e,senderId:1,seq:0,data:randomBytes(59)});
  const outA=resealLabHop({inputKey:ingressA,outputKey,packet:aa,hopSeq:0});
  const outB=resealLabHop({inputKey:ingressB,outputKey,packet:bb,hopSeq:1});
  const r=evaluateTimeOnlyLab({
   captureA:pcap([[100,aa]]),captureB:pcap([[140,bb]]),
   captureEgress:pcap([[165,outA],[180,outB],[200,randomBytes(168)]]),
   outputHopKey:outputKey,endToEndKey:e2e,
   inputHopAKey:ingressA,inputHopBKey:ingressB,maxLagMs:250,
  });
  assert.equal(r.data.total,2);
  assert.equal(r.data.correct,1);
  assert.equal(r.data.incorrect,1);
  assert.equal(r.data.accuracyOnGuessed,.5);
  assert.equal(r.data.majoritySourceBaseline,.5);
  assert.equal(r.cover.total,1);
  assert.equal(r.cover.guessedSource,1);
  assert.equal(r.attackerKeysProvided,false);
  assert.equal(r.oracleKeysUsedForScoringOnly,true);
  assert.equal(r.physicalHosts,1);
  assert.deepEqual(r.authenticatedMessageDelayMs,{count:2,p50:40,p95:65,max:65,
    truthKeysNeverGivenToAttacker:true});
 }finally{for(const k of [ingressA,ingressB,outputKey,e2e])k.fill(0);}
});
test('wrong end-to-end key cannot silently establish scoring ground truth',()=>{
 const a=randomBytes(32),b=randomBytes(32),out=randomBytes(32),
   e2e=randomBytes(32),wrong=randomBytes(32);
 try{
  const inA=sealNestedLab({hopKey:a,endToEndKey:e2e,senderId:0,seq:0,data:randomBytes(59)});
  const inB=sealNestedLab({hopKey:b,endToEndKey:e2e,senderId:1,seq:0,data:randomBytes(59)});
  assert.throws(()=>evaluateTimeOnlyLab({
   captureA:pcap([[100,inA]]),captureB:pcap([[100,inB]]),
   captureEgress:pcap([[130,resealLabHop({inputKey:a,outputKey:out,packet:inA,hopSeq:0})],
      [150,resealLabHop({inputKey:b,outputKey:out,packet:inB,hopSeq:1})]]),
   outputHopKey:out,endToEndKey:wrong,
  }),/insufficient/);
 }finally{for(const k of [a,b,out,e2e,wrong])k.fill(0);}
});
