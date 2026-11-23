/** Activity-independent fixed rate with encrypted cover and optional FEC shards. */
import {createHmac, hkdfSync} from 'node:crypto';
import {stratifiedSlots, FRAME_BYTES} from './transport.mjs';

function hmacBytes(key, window, purpose){return createHmac('sha256',key).update(`v14/${purpose}/${window}`).digest();}
function prng(seed){
 let counter=0;return (n)=>{
  if(!Number.isInteger(n)||n<1)throw new RangeError('n');
  const limit=Math.floor(0x100000000/n)*n;
  let v;
  do {v=createHmac('sha256',seed).update(String(counter++)).digest().readUInt32BE(0);} while(v>=limit);
  return v%n;
 };
}
export function scheduleKey(masterSecret,sessionId){
 if(!Buffer.isBuffer(masterSecret)||masterSecret.length!==32||!Buffer.isBuffer(sessionId)||sessionId.length!==16)throw new RangeError('Need 32B master and 16B unique session');
 return Buffer.from(hkdfSync('sha256',masterSecret,sessionId,Buffer.from('QUANTIC/SCATTERING/V14/SCHEDULER'),32));
}
/** No signal-dependent decisions: schedule is derived solely from public budget,
 * secret session key and predetermined window index. This is not a claim of
 * traffic-analysis resistance against unmodelled real network metadata. */
export function dataPositions(key,window,{slots=28,shards=16,mode='keyed_stratified'}={}){
 if(!Buffer.isBuffer(key)||key.length!==32||!Number.isSafeInteger(window)||window<0||!Number.isInteger(slots)||slots<shards||shards<1||shards>slots)throw new RangeError('Invalid schedule arguments');
 if(mode==='public_stratified')return stratifiedSlots(slots,shards);
 const next=prng(hmacBytes(key,window,mode));
 if(mode==='keyed_antipodal'){
  if(slots%2!==0||shards%2!==0)throw new RangeError('Antipodal schedule requires an even slot and shard count');
  const half=slots/2, pairs=shards/2;
  if(pairs>half)throw new RangeError('Too many shards');
  const all=Array.from({length:half},(_,i)=>i);
  for(let i=all.length-1;i>0;i--){const j=next(i+1);[all[i],all[j]]=[all[j],all[i]];}
  const chosen=all.slice(0,pairs).sort((a,b)=>a-b);
  return [...chosen,...chosen.map(x=>x+half)];
 }
 if(mode==='keyed_stratified'){
  return Array.from({length:shards},(_,i)=>{
   const low=Math.floor(i*slots/shards),high=Math.floor((i+1)*slots/shards);
   return low+next(high-low);
  });
 }
 if(mode==='keyed_uniform'){
  const all=Array.from({length:slots},(_,i)=>i);
  for(let i=all.length-1;i>0;i--){const j=next(i+1);[all[i],all[j]]=[all[j],all[i]];}
  return all.slice(0,shards).sort((a,b)=>a-b);
 }
 throw new RangeError('Unknown schedule');
}
export function emitWindow(sender,sessionScheduleKey,window,{slots=28,mode='keyed_stratified',shards=null}={}){
 if(shards!==null&&(!Array.isArray(shards)||shards.length!==16))throw new RangeError('Require 16 data shards or no data');
 const placement=dataPositions(sessionScheduleKey,window,{slots,shards:16,mode});
 const bySlot=new Map(placement.map((slot,i)=>[slot,shards?.[i]??null]));
 const frames=Array.from({length:slots},(_,i)=>{
  const shard=bySlot.get(i);
  return shard?sender.nextShard(shard):sender.nextCover();
 });
 if(!frames.every(x=>x.length===FRAME_BYTES))throw new Error('Frame size invariant violated');
 return {frames,placement};
}
