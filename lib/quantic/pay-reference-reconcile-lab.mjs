// Bounded experimental IBLT reconciliation of SHA-384 proof references.
// Not an authenticated network protocol. Require independent full-batch validation
// and a trusted/certified commitment before acting on a reconstructed set.
import {createHash,randomBytes} from 'node:crypto';
const MAX=1024,HEADER=104,CELL=66,K=3,WIDTHS=[32,64,128,256,512];
const MAGIC=Buffer.from('QRS1'),check=x=>{if(!x)throw Error('Reconciliation refused');};
const hex=(s,n)=>typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);
function items(refs){
 check(Array.isArray(refs)&&refs.length<=MAX&&refs.every(r=>hex(r,96))&&new Set(refs).size===refs.length);
 return [...refs].sort();
}
function digest(domain,...parts){const h=createHash('sha384').update(domain+'\0');for(const p of parts)h.update(p);return h.digest();}
function commitment(scope,refs){return digest('quantic-reconcile-set/v1',Buffer.from(scope,'hex'),...items(refs).map(r=>Buffer.from(r,'hex')));}
function fingerprint(scope,salt,id){return digest('quantic-reconcile-cell/v1',scope,salt,id).subarray(0,16);}
function positions(scope,salt,id,n){
 const d=digest('quantic-reconcile-index/v1',scope,salt,id),out=[];
 for(let k=0;k<K;k++){let p=d.readUInt32BE(4*k)%n;while(out.includes(p))p=(p+1)%n;out.push(p);}return out;
}
const blank=n=>Array.from({length:n},()=>({count:0,id:Buffer.alloc(48),tag:Buffer.alloc(16)}));
function xor(a,b){for(let i=0;i<a.length;i++)a[i]^=b[i];}
function apply(cells,scope,salt,id,sign){
 const tag=fingerprint(scope,salt,id);
 for(const i of positions(scope,salt,id,cells.length)){const c=cells[i];c.count+=sign;xor(c.id,id);xor(c.tag,tag);}
}
export function buildReferenceSketch({scope,refs,width=64,salt=randomBytes(16)}){
 check(hex(scope,64)&&WIDTHS.includes(width)&&Buffer.isBuffer(salt)&&salt.length===16);
 const sorted=items(refs),s=Buffer.from(scope,'hex'),cells=blank(width);
 for(const r of sorted)apply(cells,s,salt,Buffer.from(r,'hex'),1);
 const b=Buffer.alloc(HEADER+width*CELL);MAGIC.copy(b);s.copy(b,4);salt.copy(b,36);b.writeUInt16BE(sorted.length,52);b.writeUInt16BE(width,54);commitment(scope,sorted).copy(b,56);
 cells.forEach((c,i)=>{const o=HEADER+i*CELL;b.writeInt16BE(c.count,o);c.id.copy(b,o+2);c.tag.copy(b,o+50);});return b;
}
export function reconcileReferenceSketch({scope,localRefs,sketch}){
 check(hex(scope,64)&&Buffer.isBuffer(sketch)&&sketch.length>=HEADER&&sketch.subarray(0,4).equals(MAGIC)&&sketch.subarray(4,36).equals(Buffer.from(scope,'hex')));
 const targetCount=sketch.readUInt16BE(52),n=sketch.readUInt16BE(54);
 check(targetCount<=MAX&&WIDTHS.includes(n)&&sketch.length===HEADER+n*CELL);
 const s=Buffer.from(scope,'hex'),salt=sketch.subarray(36,52),expected=sketch.subarray(56,104),local=items(localRefs),target=new Set(local),cells=blank(n);
 for(let i=0;i<n;i++){const o=HEADER+i*CELL,c=cells[i];c.count=sketch.readInt16BE(o);check(c.count>=0&&c.count<=targetCount);sketch.copy(c.id,0,o+2,o+50);sketch.copy(c.tag,0,o+50,o+66);}
 for(const r of local)apply(cells,s,salt,Buffer.from(r,'hex'),-1);
 const added=[],removed=[],seen=new Set();
 function pure(i){const c=cells[i];return Math.abs(c.count)===1&&c.tag.equals(fingerprint(s,salt,c.id))&&positions(s,salt,c.id,n).includes(i);}
 const queue=[];for(let i=0;i<n;i++)if(pure(i))queue.push(i);
 for(let j=0;j<queue.length;j++){
  check(j<=n+K*2*MAX&&seen.size<=2*MAX);
  const i=queue[j];if(!pure(i))continue;
  const c=cells[i],sign=c.count,id=Buffer.from(c.id),r=id.toString('hex');check(!seen.has(r));seen.add(r);
  if(sign===1){check(!target.has(r));target.add(r);added.push(r);}else{check(target.delete(r));removed.push(r);}
  const touched=positions(s,salt,id,n);apply(cells,s,salt,id,-sign);
  for(const p of touched)if(pure(p))queue.push(p);
 }
 // Never return partial differences. A retry must use a separately scheduled
 // fixed profile or abort; no data-dependent packet scheduling here.
 check(cells.every(c=>c.count===0&&c.id.every(x=>x===0)&&c.tag.every(x=>x===0)));
 const refs=[...target].sort();check(refs.length===targetCount&&commitment(scope,refs).equals(expected));
 return Object.freeze({refs:Object.freeze(refs),missing:Object.freeze(added.sort()),extra:Object.freeze(removed.sort())});
}
