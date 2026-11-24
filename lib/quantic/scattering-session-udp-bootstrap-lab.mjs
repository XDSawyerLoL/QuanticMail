// Public, bounded bootstrap framing. NOT a cover channel and NOT authenticated
// until the complete hybrid handshake verifies. Only use with explicitly
// pinned peers and a fresh public context. No shared bootstrap secret.
import {createHash} from 'node:crypto';
import {sessionWireSize,packSession,unpackSession} from './scattering-session-wire-lab.mjs';
const check=x=>{if(!x)throw Error('UDP handshake fragment refused');};
const payload=1024,header=24,types={hello:1,response:2,finish:3};
function binding(context){
 check(context&&/^[a-f0-9]{96}$/.test(context.channel)&&Number.isSafeInteger(context.generation)&&context.generation>=0&&context.generation<=65535&&/^[a-f0-9]{96}$/.test(context.previous));
 return createHash('sha256').update(JSON.stringify(['quantic-public-bootstrap/lab/v1',context.channel,context.generation,context.previous])).digest().subarray(0,16);
}
export function fragmentSession(kind,frame,context){
 check(Object.hasOwn(types,kind));const wire=packSession(kind,frame),tag=binding(context),count=Math.ceil(wire.length/payload);
 return Array.from({length:count},(_,i)=>{
  const body=wire.subarray(i*payload,(i+1)*payload),h=Buffer.alloc(header);
  h.write('QHUB',0,'ascii');h[4]=1;h[5]=types[kind];h[6]=i;h[7]=count;tag.copy(h,8);
  return Buffer.concat([h,body]);
 });
}
export function openSessionAssembly(kind,context){
 check(Object.hasOwn(types,kind));const tag=binding(context),size=sessionWireSize(kind),count=Math.ceil(size/payload),parts=new Array(count).fill(null);
 let done=false,filled=0;
 return Object.freeze({
  push(packet){
   if(done)return null;
   // Invalid traffic is ignored without allocation proportional to attacker input.
   if(!Buffer.isBuffer(packet)||packet.length<header||packet.length>header+payload||packet.subarray(0,4).toString('ascii')!=='QHUB'||packet[4]!==1||packet[5]!==types[kind]||packet[7]!==count||!packet.subarray(8,24).equals(tag))return null;
   const index=packet[6];if(index>=count||packet.length!==header+Math.min(payload,size-index*payload))return null;
   const data=packet.subarray(header);
   if(parts[index]){
    // Conflicting copies are an ambiguity, not a reason to trust the latest.
    if(!parts[index].equals(data)){done=true;throw Error('Conflicting UDP handshake fragments');}
    return null;
   }
   parts[index]=Buffer.from(data);filled++;
   if(filled!==count)return null;
   done=true;return unpackSession(kind,Buffer.concat(parts));
  }
 });
}
