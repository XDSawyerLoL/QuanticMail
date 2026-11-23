/** Experimental systematic Reed-Solomon erasure code, 8 data + 8 parity.
 * Cauchy generator over GF(256), primitive polynomial 0x11d.
 * Not audited for side channels; DO NOT use as production cryptographic code.
 */
export const DATA_SHARDS=8, TOTAL_SHARDS=16, SHARD_SIZE=118;
const ex=new Uint8Array(512), lg=new Uint8Array(256);
let val=1;
for(let i=0;i<255;i++){ex[i]=val;lg[val]=i;val*=2;if(val>=256)val^=0x11d;}
for(let i=255;i<512;i++)ex[i]=ex[i-255];
export function gfMul(a,b){return a===0||b===0?0:ex[lg[a]+lg[b]];}
export function gfInv(a){if(a===0)throw new RangeError('0 is not invertible');return ex[255-lg[a]];}
function rowFor(shard){
 if(!Number.isInteger(shard)||shard<0||shard>=TOTAL_SHARDS)throw new RangeError('shard index');
 if(shard<DATA_SHARDS)return Array.from({length:DATA_SHARDS},(_,j)=>Number(shard===j));
 // Cauchy matrix, x in 0..7, y in 8..15 => all denominators nonzero.
 return Array.from({length:DATA_SHARDS},(_,j)=>gfInv((shard-DATA_SHARDS)^(DATA_SHARDS+j)));
}
function inverse(rows){
 const n=DATA_SHARDS;
 const a=rows.map((r,i)=>[...r,...Array.from({length:n},(_,j)=>Number(i===j))]);
 for(let j=0;j<n;j++){
  let pivot=j;while(pivot<n&&a[pivot][j]===0)pivot++;
  if(pivot===n)throw new Error('Singular erasure matrix');
  if(pivot!==j)[a[j],a[pivot]]=[a[pivot],a[j]];
  const inv=gfInv(a[j][j]);for(let k=0;k<2*n;k++)a[j][k]=gfMul(a[j][k],inv);
  for(let i=0;i<n;i++)if(i!==j){const f=a[i][j];if(f!==0)for(let k=0;k<2*n;k++)a[i][k]^=gfMul(f,a[j][k]);}
 }
 return a.map(r=>r.slice(n));
}
function checkShard(data){if(!Buffer.isBuffer(data)||data.length!==SHARD_SIZE)throw new TypeError('Every shard must contain exactly 118 bytes');}
export function encodeShards(data){
 if(!Array.isArray(data)||data.length!==DATA_SHARDS)throw new RangeError('8 data shards required');
 data.forEach(checkShard);
 const parity=[];
 for(let id=DATA_SHARDS;id<TOTAL_SHARDS;id++){
  const row=rowFor(id),shard=Buffer.alloc(SHARD_SIZE);
  for(let j=0;j<DATA_SHARDS;j++)for(let k=0;k<SHARD_SIZE;k++)shard[k]^=gfMul(row[j],data[j][k]);
  parity.push(shard);
 }
 return [...data.map(x=>Buffer.from(x)),...parity];
}
export function recoverShards(received){
 // Map<shardId, Buffer> or array of [id,Buffer] pairs; 8 distinct shards enough.
 const entries=received instanceof Map?[...received]:received;
 if(!Array.isArray(entries))throw new TypeError('Map or pair list required');
 const seen=new Set(),take=[];
 for(const entry of entries){
  if(!Array.isArray(entry)||entry.length!==2)throw new TypeError('Invalid shard pair');
  const [id,buf]=entry;checkShard(buf);rowFor(id);
  if(!seen.has(id)){seen.add(id);take.push(entry);if(take.length===DATA_SHARDS)break;}
 }
 if(take.length<DATA_SHARDS)return null;
 const inv=inverse(take.map(([i])=>rowFor(i))),original=[];
 for(let j=0;j<DATA_SHARDS;j++){
  const shard=Buffer.alloc(SHARD_SIZE);
  for(let k=0;k<DATA_SHARDS;k++)for(let t=0;t<SHARD_SIZE;t++)shard[t]^=gfMul(inv[j][k],take[k][1][t]);
  original.push(shard);
 }
 return original;
}
/** Exhaustive independent rank check over all C(16,8)=12,870 receive subsets.
 * This checks GF(256) matrix invertibility, not end-to-end network security.
 */
export function verifyAllEightShardSubsets(){
 let checked=0,failures=0;
 const chosen=[];
 function walk(start){
  if(chosen.length===DATA_SHARDS){checked++;
   try{inverse(chosen.map(rowFor));}catch{failures++;}
   return;
  }
  for(let x=start;x<=TOTAL_SHARDS-(DATA_SHARDS-chosen.length);x++){
   chosen.push(x);walk(x+1);chosen.pop();
  }
 }
 walk(0);
 return {checked,failures,pass:checked===12870&&failures===0};
}
