// Passive, laboratory-only Ethernet/IPv4/UDP PCAP correlation detector.
// Input contains only synthetic cover cells; no user's traffic or keys.
import {createHash} from 'node:crypto';
const CAPTURE_LIMIT = 16 * 1024 * 1024;
const MAX_RECORDS = 100000;
const CELL_BYTES = 168;
function checked(ok, why) {if (!ok) throw new Error(why);}
export function parseLabPcap(bytes) {
  checked(Buffer.isBuffer(bytes) && bytes.length >= 24 && bytes.length <= CAPTURE_LIMIT, 'pcap size');
  const magic = bytes.subarray(0,4).toString('hex');
  const layouts={d4c3b2a1:[true,1000],a1b2c3d4:[false,1000],"4d3cb2a1":[true,1000000],a1b23c4d:[false,1000000]};
  checked(Object.hasOwn(layouts,magic),'unsupported classic pcap');
  const [le,msFactor] = layouts[magic];
  const u16 = (offset) => le?bytes.readUInt16LE(offset):bytes.readUInt16BE(offset);
  const u32 = (offset) => le?bytes.readUInt32LE(offset):bytes.readUInt32BE(offset);
  checked(u16(4)===2&&u16(6)===4&&u32(20)===1,'expected Ethernet pcap v2.4');
  const snaplen=u32(16);
  checked(snaplen>=42&&snaplen<=65535,'invalid snaplen');
  const result=[]; let offset=24,recordCount=0,ignored=0;
  while(offset<bytes.length){
    checked(offset+16<=bytes.length,'truncated record header');
    const sec=u32(offset), subseconds=u32(offset+4), captured=u32(offset+8), original=u32(offset+12);
    offset+=16;
    checked(++recordCount<=MAX_RECORDS && captured>0 && captured<=snaplen && original>=captured && offset+captured<=bytes.length,'bad record length');
    const frame=bytes.subarray(offset,offset+captured);offset+=captured;
    // Ethernet 14B + IPv4 20B + UDP 8B. Only synthetic UDP/168 cells are counted.
    if(frame.length<42 || frame.readUInt16BE(12)!==0x0800){ignored++;continue;}
    const ip=14,version=frame[ip]>>4,ihl=(frame[ip]&0x0f)*4;
    if(version!==4||ihl<20||ip+ihl+8>frame.length||frame[ip+9]!==17){ignored++;continue;}
    // Refuse IP fragmentation; the lab uses only small 168-byte datagrams.
    if((frame.readUInt16BE(ip+6)&0x3fff)!==0){ignored++;continue;}
    const udp=ip+ihl,udpLength=frame.readUInt16BE(udp+4),payloadLength=udpLength-8;
    if(payloadLength!==CELL_BYTES || udp+udpLength>frame.length){ignored++;continue;}
    const senderPort=frame.readUInt16BE(udp),recipientPort=frame.readUInt16BE(udp+2);
    const packet=frame.subarray(udp+8,udp+8+CELL_BYTES);
    const hash=createHash('sha256').update(packet).digest('hex');
    const timestampMs=sec*1000+subseconds/msFactor;
    result.push({hash,timestampMs,senderPort,recipientPort});
  }
  checked(result.length>0,'no 168-byte synthetic UDP frames');
  return {packets:result,ignored,records:recordCount};
}
export function assessCrossHopLinkability(ingressA,ingressB,egress){
  const a=parseLabPcap(ingressA),b=parseLabPcap(ingressB),out=parseLabPcap(egress);
  const known=new Map();
  for(const [id,pcap] of [['A',a],['B',b]]){
    for(const pkt of pcap.packets){
      checked(!known.has(pkt.hash),'duplicate or cross-source ciphertext in lab');
      known.set(pkt.hash,{sender:id,time:pkt.timestampMs});
    }
  }
  const counts={A:0,B:0,unmatched:0};let matching=0,reused=0;
  const seen=new Set();const lagSamples=[];
  for(const pkt of out.packets){
    const matched=known.get(pkt.hash);
    if(!matched){counts.unmatched++;continue;}
    if(seen.has(pkt.hash)){reused++;continue;}
    seen.add(pkt.hash);counts[matched.sender]++;matching++;
    lagSamples.push(pkt.timestampMs-matched.time);
  }
  lagSamples.sort((x,y)=>x-y);
  const q=p=>lagSamples.length?+(lagSamples[Math.ceil(lagSamples.length*p)-1]??lagSamples[0]).toFixed(3):null;
  return {
    evidenceLevel:'two-real-pacers-one-opaque-queue-relay-one-real-pacer-on-virtual-link',
    physicalHosts:1,relays:1,senders:2,passiveIngressAndEgress:true,
    observer:'global passive exact-ciphertext equality with both ingress and egress visible',
    // Important negative control: the relay does NOT remove linkable packets.
    ingress:{A:a.packets.length,B:b.packets.length},
    egress:{cells:out.packets.length,matchedUnique:matching,coverOrUnmatched:counts.unmatched,
      repeatedCiphertext:reused,matchedPerSender:{A:counts.A,B:counts.B}},
    matchRate:+(matching/out.packets.length).toFixed(6),
    ingressMatchedRate:+(matching/(a.packets.length+b.packets.length)).toFixed(6),
    relayDelayMs:{p50:q(.5),p95:q(.95)},
    securityConclusion:'Negative control: unchanged ciphertext is linkable across hops; matching does not identify real persons and no anonymity or unlinkability is demonstrated.',
  };
}
