import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {stripeLengths,splitScatteringLab,joinScatteringLab} from '../lib/quantic/scattering-stripes-lab.mjs';
import {sealReliable,openReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
test('bounded fixed lane profiles reconstruct exact binary payloads and reject corruption',()=>{
 for(const lanes of [1,2,4])for(const n of [1,8192,8193,65537,530123,1048576]){
  const b=randomBytes(n),{manifest,parts}=splitScatteringLab(b,lanes);
  assert.deepEqual(parts.map(p=>p.length),stripeLengths(n,lanes));
  assert.equal(parts.reduce((s,p)=>s+p.length,0),n);
  assert.deepEqual(joinScatteringLab(manifest,parts),b);
  const bad=parts.map(p=>Buffer.from(p));bad[0][0]^=1;
  assert.throws(()=>joinScatteringLab(manifest,bad));
  assert.throws(()=>joinScatteringLab(manifest,parts.slice(1)));
  assert.throws(()=>joinScatteringLab({...manifest,size:n+1},parts));
  assert.throws(()=>joinScatteringLab({...manifest,digest:'0'.repeat(64)},parts));
  if(lanes>1&&n>8192){const swapped=[...parts];[swapped[0],swapped[1]]=[swapped[1],swapped[0]];assert.throws(()=>joinScatteringLab(manifest,swapped));}
 }
 for(const lanes of [0,3,5,100])assert.throws(()=>stripeLengths(1024,lanes));
 for(const n of [0,-1,4194305,Infinity,1.5])assert.throws(()=>stripeLengths(n,4));
});
test('authenticated cells cannot be decoded on a lane with a different key',()=>{
 const keys=Array.from({length:4},()=>randomBytes(32));
 for(let i=0;i<4;i++){
  const data=randomBytes(128),cell=sealReliable(keys[i],{seq:0,ack:0,data});
  assert.equal(cell.length,168);assert.deepEqual(openReliable(keys[i],cell).data,data);
  for(let j=0;j<4;j++)if(i!==j)assert.equal(openReliable(keys[j],cell),null);
  const tampered=Buffer.from(cell);tampered[40]^=1;assert.equal(openReliable(keys[i],tampered),null);
 }
});
