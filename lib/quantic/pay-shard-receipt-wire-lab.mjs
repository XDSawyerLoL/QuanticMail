// Lossless cross-shard receipt bundle. One header and one real quorum
// certificate per source block, no signature aggregation or verification bypass.
import {packPayFinal,unpackPayFinal} from './pay-certificate-wire-lab.mjs';
const check=x=>{if(!x)throw Error('Shard receipt bundle refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^demo-[a-z0-9]{1,24}$/.test(x);
const integer=(x,a,b)=>Number.isSafeInteger(x)&&x>=a&&x<=b;
function sig(s,n){check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
const hkeys=['network','shard','height','previous','operationsRoot','stateRoot'];
const rkeys=['header','certificate','proof','index','count','siblings'];
const MAX=64,MAX_WIRE=400000;
const sortedHeader=h=>{check(exact(h,hkeys)&&id(h.shard)&&integer(h.height,1,256)&&['network','previous','operationsRoot','stateRoot'].every(k=>hex(h[k])));return Object.fromEntries(hkeys.map(k=>[k,h[k]]));};
function u16(n){const b=Buffer.alloc(2);b.writeUInt16BE(n);return b;}
function u32(n){const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;}
const text=s=>Buffer.concat([Buffer.from([Buffer.byteLength(s)]),Buffer.from(s)]);
export function packShardReceipts(receipts){
 check(Array.isArray(receipts)&&integer(receipts.length,1,MAX)&&receipts.every(r=>exact(r,rkeys)));
 const first=receipts[0],header=sortedHeader(first.header),count=first.count,cert=packPayFinal(first.certificate,16);
 check(integer(count,receipts.length,MAX));
 const out=[Buffer.from('QSR1'),Buffer.from(header.network,'hex'),text(header.shard),u16(header.height),...['previous','operationsRoot','stateRoot'].map(k=>Buffer.from(header[k],'hex')),u32(cert.length),cert,Buffer.from([count,receipts.length])];
 let last=-1;
 for(const r of receipts){
  check(JSON.stringify(sortedHeader(r.header))===JSON.stringify(header)&&r.count===count&&packPayFinal(r.certificate,16).equals(cert)&&integer(r.index,last+1,count-1)&&Array.isArray(r.siblings)&&r.siblings.length===Math.ceil(Math.log2(count))&&r.siblings.every(hex));last=r.index;
  const p=r.proof,i=p?.intent;
  check(exact(p,['intent','signature','pqSignature'])&&exact(i,['network','payer','payee','amount','nonce'])&&i.network===header.network&&id(i.payer)&&id(i.payee)&&i.payer!==i.payee&&integer(i.amount,1,1000000000)&&hex(i.nonce));
  out.push(Buffer.from([r.index]),text(i.payer),text(i.payee),u32(i.amount),Buffer.from(i.nonce,'hex'),sig(p.signature,64),sig(p.pqSignature,3309),...r.siblings.map(s=>Buffer.from(s,'hex')));
 }
 const b=Buffer.concat(out);check(b.length<=MAX_WIRE);return b;
}
export function unpackShardReceipts(b){
 check(Buffer.isBuffer(b)&&b.length<=MAX_WIRE);let o=0;
 function take(n){check(integer(n,0,b.length)&&o+n<=b.length);const v=b.subarray(o,o+n);o+=n;return v;}
 const str=()=>{const n=take(1)[0];check(integer(n,6,29));const s=take(n).toString('ascii');check(id(s));return s;};
 const h=()=>take(32).toString('hex');
 check(take(4).toString()==='QSR1');
 const header={network:h(),shard:str(),height:take(2).readUInt16BE(),previous:h(),operationsRoot:h(),stateRoot:h()};
 const certificate=unpackPayFinal(take(take(4).readUInt32BE()),16),count=take(1)[0],n=take(1)[0];
 check(integer(n,1,MAX)&&integer(count,n,MAX));
 const receipts=[];for(let j=0;j<n;j++){
  const index=take(1)[0],intent={network:header.network,payer:str(),payee:str(),amount:take(4).readUInt32BE(),nonce:h()};
  const proof={intent,signature:take(64).toString('base64url'),pqSignature:take(3309).toString('base64url')};
  const siblings=Array.from({length:Math.ceil(Math.log2(count))},h);
  receipts.push({header,certificate,proof,index,count,siblings});
 }
 check(o===b.length&&packShardReceipts(receipts).equals(b));return receipts;
}
