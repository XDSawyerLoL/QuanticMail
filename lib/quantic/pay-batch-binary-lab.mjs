// Synthetic batch wire codec. Structural validation only; the existing hybrid
// signature verifier and consensus must independently validate decoded proofs.
import {Buffer} from 'node:buffer';
const check=v=>{if(!v)throw Error('Batch binary refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const hex=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const id=v=>typeof v==='string'&&/^demo-[a-z]{1,24}$/.test(v);
const safe=v=>Number.isSafeInteger(v)&&v>=0;
const magic=Buffer.from('QBT1'),ROW=3419,HEADER=111,MAX=1024;
const intentKeys=['network','sequence','previousRoot','payer','payee','payerPin','payerPQPin','payeePin','payeePQPin','cents','currency','nonce','issued','expires','simulationOnly'];
function sig(s,n){check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
export function encodePayBatchBinary({proofs,time,value}){
 check(Array.isArray(proofs)&&proofs.length>=1&&proofs.length<=MAX&&safe(time)&&hex(value));
 const first=proofs[0]?.intent;check(first&&hex(first.network)&&hex(first.previousRoot)&&Number.isInteger(first.sequence)&&first.sequence>=1&&first.sequence<=256);
 const accounts=new Map(),rows=[];
 function account(name,pin,pqPin){
  check(id(name)&&hex(pin)&&hex(pqPin)&&pin!==pqPin);
  if(accounts.has(name)){const a=accounts.get(name);check(a.pin===pin&&a.pqPin===pqPin);return a.index;}
  check(accounts.size<16);const index=accounts.size;accounts.set(name,{name,pin,pqPin,index});return index;
 }
 for(const p of proofs){
  check(exact(p,['intent','signature','pqSignature'])&&exact(p.intent,intentKeys));const i=p.intent;
  check(i.network===first.network&&i.previousRoot===first.previousRoot&&i.sequence===first.sequence&&i.payer!==i.payee&&Number.isInteger(i.cents)&&i.cents>=1&&i.cents<=160000&&hex(i.nonce)&&safe(i.issued)&&safe(i.expires)&&i.expires-i.issued===120000&&i.currency==='EUR'&&i.simulationOnly===true);
  const row=Buffer.alloc(ROW);row[0]=account(i.payer,i.payerPin,i.payerPQPin);row[1]=account(i.payee,i.payeePin,i.payeePQPin);row.writeUInt32BE(i.cents,2);Buffer.from(i.nonce,'hex').copy(row,6);row.writeBigUInt64BE(BigInt(i.issued),38);sig(p.signature,64).copy(row,46);sig(p.pqSignature,3309).copy(row,110);rows.push(row);
 }
 const head=Buffer.alloc(HEADER);magic.copy(head);Buffer.from(first.network,'hex').copy(head,4);Buffer.from(first.previousRoot,'hex').copy(head,36);Buffer.from(value,'hex').copy(head,68);head.writeBigUInt64BE(BigInt(time),100);head.writeUInt16BE(first.sequence,108); // count follows table
 head[110]=accounts.size;
 const table=[...accounts.values()].map(a=>Buffer.concat([Buffer.from([a.name.length]),Buffer.from(a.name,'ascii'),Buffer.from(a.pin,'hex'),Buffer.from(a.pqPin,'hex')]));
 const count=Buffer.alloc(2);count.writeUInt16BE(rows.length);
 return Buffer.concat([head,...table,count,...rows]);
}
export function decodePayBatchBinary(b){
 check(Buffer.isBuffer(b)&&b.length>=HEADER+2&&b.length<=HEADER+16*94+2+MAX*ROW&&b.subarray(0,4).equals(magic));
 const network=b.subarray(4,36).toString('hex'),previousRoot=b.subarray(36,68).toString('hex'),value=b.subarray(68,100).toString('hex'),time=Number(b.readBigUInt64BE(100)),sequence=b.readUInt16BE(108),n=b[110];
 check(safe(time)&&sequence>=1&&sequence<=256&&n>=2&&n<=16);
 let o=HEADER;const accounts=[],seen=new Set(),pins=new Set();
 for(let i=0;i<n;i++){
  check(o<b.length);const len=b[o++];check(len>=6&&len<=29&&o+len+64<=b.length);
  const name=b.subarray(o,o+len).toString('latin1');o+=len;const pin=b.subarray(o,o+32).toString('hex'),pqPin=b.subarray(o+32,o+64).toString('hex');o+=64;
  check(id(name)&&!seen.has(name)&&pin!==pqPin&&!pins.has(pin)&&!pins.has(pqPin));seen.add(name);pins.add(pin);pins.add(pqPin);accounts.push({name,pin,pqPin});
 }
 check(o+2<=b.length);const count=b.readUInt16BE(o);o+=2;check(count>=1&&count<=MAX&&b.length===o+count*ROW);
 const proofs=[],used=new Set();
 for(let i=0;i<count;i++,o+=ROW){
  const payer=accounts[b[o]],payee=accounts[b[o+1]],cents=b.readUInt32BE(o+2),issued=Number(b.readBigUInt64BE(o+38));
  check(payer&&payee&&payer!==payee&&cents>=1&&cents<=160000&&safe(issued)&&issued<=Number.MAX_SAFE_INTEGER-120000);used.add(b[o]);used.add(b[o+1]);
  proofs.push({intent:{network,sequence,previousRoot,payer:payer.name,payee:payee.name,payerPin:payer.pin,payerPQPin:payer.pqPin,payeePin:payee.pin,payeePQPin:payee.pqPin,cents,currency:'EUR',nonce:b.subarray(o+6,o+38).toString('hex'),issued,expires:issued+120000,simulationOnly:true},signature:b.subarray(o+46,o+110).toString('base64url'),pqSignature:b.subarray(o+110,o+ROW).toString('base64url')});
 }
 check(used.size===n);
 const result={proofs,time,value};check(encodePayBatchBinary(result).equals(b));return result;
}
