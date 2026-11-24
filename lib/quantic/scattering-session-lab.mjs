// Synthetic authenticated endpoint handshake. No PKI, persistence, network
// scheduling or atomic peer cutover. Provision identity keys out of band.
import * as c from 'node:crypto';
const check=x=>{if(!x)throw Error('Hybrid session refused');};
const raw=x=>Buffer.from(JSON.stringify(x));
const hash=b=>c.createHash('sha384').update(b).digest();
const b64=b=>b.toString('base64url');
const hex=(s,n)=>typeof s==='string'&&s.length===n&&/^[a-f0-9]+$/.test(s);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const der=k=>k.export({format:'der',type:'spki'});
function bytes(s,n){check(typeof s==='string'&&s.length===Math.ceil(n*8/6)&&/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');check(b.length===n&&b64(b)===s);return b;}
function pk(s,n,type){const b=bytes(s,n),k=c.createPublicKey({key:b,format:'der',type:'spki'});check(k.asymmetricKeyType===type&&der(k).equals(b));if(type==='ec')check(k.asymmetricKeyDetails.namedCurve==='prime256v1');return k;}
function pin(k){return hash(der(k)).toString('hex');}
function classicalKey(k){return k?.asymmetricKeyType==='ed25519'||k?.asymmetricKeyType==='ec'&&k.asymmetricKeyDetails?.namedCurve==='prime256v1';}
function identity(keys,privateKeys){check(keys?.classical?.type==='public'&&classicalKey(keys.classical)&&keys?.pq?.type==='public'&&keys.pq.asymmetricKeyType==='ml-dsa-65');if(privateKeys)for(const t of ['classical','pq'])check(privateKeys[t]?.type==='private'&&pin(c.createPublicKey(privateKeys[t]))===pin(keys[t]));return [pin(keys.classical),pin(keys.pq)];}
// Use the pinned device's actual algorithm, never a wire-selected downgrade.
function classicalSign(k,b){return k.asymmetricKeyType==='ec'?c.sign('sha256',b,{key:k,dsaEncoding:'ieee-p1363'}):c.sign(null,b,k);}
function classicalVerify(k,b,s){return k.asymmetricKeyType==='ec'?c.verify('sha256',b,{key:k,dsaEncoding:'ieee-p1363'},s):c.verify(null,b,k,s);}
function signatures(k,b){return {classical:b64(classicalSign(k.classical,b)),pq:b64(c.sign(null,b,k.pq))};}
function verify(k,b,s){check(exact(s,['classical','pq'])&&classicalVerify(k.classical,b,bytes(s.classical,64))&&c.verify(null,b,k.pq,bytes(s.pq,3309)));}
const mac=(key,role,t)=>b64(c.createHmac('sha384',key).update(raw(['quantic-mux-confirm/lab/v1',role,t])).digest());
function equalMac(a,b){check(c.timingSafeEqual(bytes(a,48),bytes(b,48)));}
export function openHybridSessionLab({role,local,privateKeys,signHandshake,peer,context}){
 check(['initiator','responder'].includes(role)&&typeof c.encapsulate==='function'&&typeof c.decapsulate==='function');
 check(exact(context,['channel','generation','previous'])&&hex(context.channel,96)&&Number.isSafeInteger(context.generation)&&context.generation>=0&&context.generation<=65535&&hex(context.previous,96)&&(context.generation===0)===(context.previous==='0'.repeat(96)));
 check((privateKeys!==undefined&&privateKeys!==null&&signHandshake===undefined)||(privateKeys===undefined&&typeof signHandshake==='function'));
 const me=identity(local,privateKeys),other=identity(peer);check(new Set([...me,...other]).size===4);const ctx=structuredClone(context),ids=role==='initiator'?[me,other]:[other,me];
 const prefix=['quantic-mux-hybrid/lab/v1',ctx.channel,ctx.generation,ctx.previous,ids];
 let state='new',ec=null,kem=null,hello=null,keys=null,transcript=null;
 function derive(ecPrivate,remote,pq,body){let z,ikm,material;try{z=c.diffieHellman({privateKey:ecPrivate,publicKey:remote});check(z.length===32&&pq.length===32);transcript=hash(raw([prefix,hello,body])).toString('hex');ikm=Buffer.concat([z,pq]);material=Buffer.from(c.hkdfSync('sha384',ikm,Buffer.from(transcript,'hex'),raw(['quantic-mux-keys/lab/v1',...prefix]),112));keys={secret:Buffer.from(material.subarray(0,32)),epoch:Buffer.from(material.subarray(32,64)),confirm:Buffer.from(material.subarray(64))};}finally{z?.fill(0);pq.fill(0);ikm?.fill(0);material?.fill(0);}}
 function close(){state='closed';ec=null;kem=null;hello=null;if(keys){for(const k of Object.values(keys))k.fill(0);keys=null;}}
 function guarded(fn){try{const value=fn();return value&&typeof value.then==='function'?value.catch(e=>{close();throw e;}):value;}catch(e){close();throw e;}}
 // An external signer receives only the exact domain-separated handshake bytes.
 // It must enforce its own identity, peer and operation authorization. This
 // interface is not itself a native-vault authorization mechanism.
 function signed(stage,bytesToSign,complete){
  state=stage;
  const accept=sig=>{check(state===stage);verify(local,bytesToSign,sig);return complete(structuredClone(sig));};
  if(!signHandshake)return accept(signatures(privateKeys,bytesToSign));
  return Promise.resolve(signHandshake(Buffer.from(bytesToSign))).then(accept);
 }
 return Object.freeze({
  begin(){return guarded(()=>{check(role==='initiator'&&state==='new');ec=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});kem=c.generateKeyPairSync('ml-kem-768');const body={nonce:b64(c.randomBytes(32)),ec:b64(der(ec.publicKey)),kem:b64(der(kem.publicKey))};return signed('signing-hello',raw([prefix,'hello',body]),sig=>{hello={body,sig};state='hello';return structuredClone(hello);});});},
  respond(input){return guarded(()=>{check(role==='responder'&&state==='new'&&exact(input,['body','sig'])&&exact(input.body,['nonce','ec','kem']));hello=structuredClone(input);verify(peer,raw([prefix,'hello',hello.body]),hello.sig);bytes(hello.body.nonce,32);const ep=pk(hello.body.ec,91,'ec'),kp=pk(hello.body.kem,1206,'ml-kem-768');ec=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});const pq=c.encapsulate(kp),body={nonce:b64(c.randomBytes(32)),ec:b64(der(ec.publicKey)),ciphertext:b64(pq.ciphertext)};derive(ec.privateKey,ep,pq.sharedKey,body);ec=null;return signed('signing-response',raw([prefix,'response',transcript]),sig=>{state='response';return {body,sig,confirm:mac(keys.confirm,'responder',transcript)};});});},
  finish(input){return guarded(()=>{check(role==='initiator'&&state==='hello'&&exact(input,['body','sig','confirm'])&&exact(input.body,['nonce','ec','ciphertext']));const body=structuredClone(input.body);bytes(body.nonce,32);const ep=pk(body.ec,91,'ec'),ct=bytes(body.ciphertext,1088);const t=hash(raw([prefix,hello,body])).toString('hex');verify(peer,raw([prefix,'response',t]),input.sig);derive(ec.privateKey,ep,c.decapsulate(kem.privateKey,ct),body);ec=null;kem=null;equalMac(input.confirm,mac(keys.confirm,'responder',transcript));state='ready';return {confirm:mac(keys.confirm,'initiator',transcript)};});},
  accept(input){return guarded(()=>{check(role==='responder'&&state==='response'&&exact(input,['confirm']));equalMac(input.confirm,mac(keys.confirm,'initiator',transcript));state='ready';});},
  take(){return guarded(()=>{check(state==='ready');const out={secret:Buffer.from(keys.secret),epoch:Buffer.from(keys.epoch),transcript,generation:ctx.generation};close();return out;});},close
 });
}
