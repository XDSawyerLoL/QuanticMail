import test from 'node:test';
import assert from 'node:assert/strict';
import {parseLabPcap,assessCrossHopLinkability} from '../lib/quantic/scattering-multihop-observer.mjs';
function payload(i){const b=Buffer.alloc(168);b.writeUInt32BE(i);return b;}
function capture(messages,sourcePort=40001,destPort=49001){
  const global=Buffer.alloc(24);global.writeUInt32LE(0xa1b2c3d4,0);global.writeUInt16LE(2,4);global.writeUInt16LE(4,6);global.writeUInt32LE(65535,16);global.writeUInt32LE(1,20);
  const records=messages.map(([time,id])=>{
    const bytes=payload(id),eth=Buffer.alloc(14),ip=Buffer.alloc(20),udp=Buffer.alloc(8);
    eth.writeUInt16BE(0x0800,12);ip[0]=0x45;ip[9]=17;ip.writeUInt16BE(20+8+168,2);
    udp.writeUInt16BE(sourcePort,0);udp.writeUInt16BE(destPort,2);udp.writeUInt16BE(8+168,4);
    const body=Buffer.concat([eth,ip,udp,bytes]);const h=Buffer.alloc(16);
    h.writeUInt32LE(1763982000,0);h.writeUInt32LE(Math.round(time*1000),4);
    h.writeUInt32LE(body.length,8);h.writeUInt32LE(body.length,12);
    return Buffer.concat([h,body]);
  });
  return Buffer.concat([global,...records]);
}
test('parses only bounded classic Ethernet IPv4 UDP 168-byte frames',()=>{
 const p=parseLabPcap(capture([[0,1],[20,2]]));
 assert.equal(p.packets.length,2);
 assert.equal(p.ignored,0);
 assert.equal(p.packets[0].recipientPort,49001);
 assert.equal(p.packets[0].hash.length,64);
});
test('unmodified relay frames are perfectly linkable even with fixed-size cover',()=>{
 const a=capture([[0,1],[20,2]]),b=capture([[0,3],[20,4]]),out=capture([[35,1],[55,4],[75,20],[95,2],[115,3],[135,21]],49999,49003);
 const r=assessCrossHopLinkability(a,b,out);
 assert.equal(r.egress.cells,6);
 assert.equal(r.egress.matchedUnique,4);
 assert.equal(r.egress.coverOrUnmatched,2);
 assert.equal(r.egress.matchedPerSender.A,2);
 assert.equal(r.egress.matchedPerSender.B,2);
 assert.equal(r.ingressMatchedRate,1);
 assert.equal(r.matchRate,.666667);
 assert.equal(r.physicalHosts,1);
 assert.equal(r.relayDelayMs.p50,35);
});
test('re-randomized ciphertext no longer matches by equality, but does not prove anonymity',()=>{
 const r=assessCrossHopLinkability(capture([[0,1]]),capture([[0,2]]),capture([[30,301],[50,302]]));
 assert.equal(r.matchRate,0);
 assert.match(r.securityConclusion,/no anonymity/);
});
test('fail closed on empty or truncated capture and repeated ingress ciphertext',()=>{
 const a=capture([[0,1]]),b=capture([[0,2]]);
 assert.throws(()=>parseLabPcap(Buffer.alloc(24)));
 assert.throws(()=>parseLabPcap(a.subarray(0,a.length-1)));
 assert.throws(()=>assessCrossHopLinkability(a,a,capture([[0,1]])));
 assert.throws(()=>parseLabPcap(Buffer.alloc(20)));
});
