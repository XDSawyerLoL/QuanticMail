// Fixed-size lossless handshake codec. Decoding is not authentication.
const check=x=>{if(!x)throw Error('Session wire refused');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const layout={hello:[['nonce',32],['ec',91],['kem',1206]],response:[['nonce',32],['ec',91],['ciphertext',1088]]};
const code={hello:1,response:2,finish:3};
const sizes={hello:4706,response:4636,finish:52};
function bytes(s,n){check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b.toString('base64url')===s);return b;}
export function sessionWireSize(kind){check(Object.hasOwn(sizes,kind));return sizes[kind];}
export function packSession(kind,m){
 check(Object.hasOwn(code,kind));const h=Buffer.from([81,72,49,code[kind]]),out=[h];
 if(kind==='finish'){check(exact(m,['confirm']));out.push(bytes(m.confirm,48));}
 else{
  check(exact(m,kind==='hello'?['body','sig']:['body','sig','confirm'])&&exact(m.body,layout[kind].map(([k])=>k))&&exact(m.sig,['classical','pq']));
  for(const [k,n] of layout[kind])out.push(bytes(m.body[k],n));
  out.push(bytes(m.sig.classical,64),bytes(m.sig.pq,3309));if(kind==='response')out.push(bytes(m.confirm,48));
 }
 const b=Buffer.concat(out);check(b.length===sizes[kind]);return b;
}
export function unpackSession(kind,b){
 check(Object.hasOwn(code,kind)&&Buffer.isBuffer(b)&&b.length===sizes[kind]&&b.subarray(0,4).equals(Buffer.from([81,72,49,code[kind]])));
 let o=4;const take=n=>{const s=b.subarray(o,o+n).toString('base64url');o+=n;return s;};let m;
 if(kind==='finish')m={confirm:take(48)};else{const body={};for(const [k,n] of layout[kind])body[k]=take(n);m={body,sig:{classical:take(64),pq:take(3309)}};if(kind==='response')m.confirm=take(48);}
 check(o===b.length&&packSession(kind,m).equals(b));return m;
}
