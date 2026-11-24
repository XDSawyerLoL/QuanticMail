// TRUSTED HOP diagnostic only. Decrypting each inbound hop here means the relay
// sees plaintext: unsuitable as a complete anonymous or end-to-end solution.
import {openReliable,sealReliable,POLICY} from '../../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
const check = (ok,msg) => {if(!ok)throw Error(msg);};
export function resealLabHop({inputKey,outputKey,packet,hopSeq}){
  check(Buffer.isBuffer(inputKey)&&inputKey.length===32&&
    Buffer.isBuffer(outputKey)&&outputKey.length===32&&
    !inputKey.equals(outputKey)&&Number.isInteger(hopSeq)&&
    hopSeq>=0&&hopSeq<POLICY.maxSeq,'invalid hop inputs or keys');
  const ingress=openReliable(inputKey,packet);
  if(!ingress||ingress.seq===null||ingress.data.length===0)return null;
  const outbound=sealReliable(outputKey,{seq:hopSeq,ack:0,data:ingress.data});
  check(outbound.length===168&&!outbound.equals(packet),'hop reseal failed');
  ingress.data.fill(0); // best effort: clear the recovered userless lab payload copy
  return outbound;
}
