import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomBytes} from 'node:crypto';
import {parsePayOperatorConfig} from '../lib/quantic/pay-operator-config.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
test('operator configuration is pinned, isolated, hybrid and four distinct local links only',()=>{
 const k=()=>{const a=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'}),b=generateKeyPairSync('ml-dsa-65').publicKey.export({type:'spki',format:'der'});return {pin:sha(a),publicKey:a.toString('base64url'),pqPin:sha(b),pqPublicKey:b.toString('base64url')}};
 const scope={signingPin:'a'.repeat(64),pqPin:'b'.repeat(64)};
 const c={format:'quantic-native-pay-operator/v1',simulationOnly:true,scope,authorities:Array.from({length:4},(_,i)=>({...k(),loopbackPort:12000+i,token:randomBytes(32).toString('hex')}))};
 const raw=Buffer.from(JSON.stringify(c));
 const result=parsePayOperatorConfig(raw,sha(raw));assert.equal(result.links.length,4);assert.equal(result.trustedAuthorities.length,4);
 assert.throws(()=>parsePayOperatorConfig(raw,'0'.repeat(64)));
 for(const alter of [x=>x.simulationOnly=false,x=>x.authorities[1].token=x.authorities[0].token,x=>x.authorities[1].loopbackPort=x.authorities[0].loopbackPort,x=>Object.assign(x.authorities[1],{pqPin:x.authorities[0].pqPin,pqPublicKey:x.authorities[0].pqPublicKey}),x=>x.authorities[0].host='example.org']){
  const bad=structuredClone(c);alter(bad);const b=Buffer.from(JSON.stringify(bad));assert.throws(()=>parsePayOperatorConfig(b,sha(b)));
 }
});
