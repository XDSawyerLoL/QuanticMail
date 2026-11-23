import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {
 twoPartyWindowsPlan,checkTwoPartyWindowsPlan,provisionTwoWindowsLab
} from '../desktop/windows-two-party-provision-lab.mjs';
import {deviceIdForPublicKeyNode} from '../lib/quantic/manifest-node.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const dir='C:\\QuanticLab\\Pair',binary='C:\\QuanticLab\\bin\\Vault-PQ-lab.exe';
const first={address:'alice~'+'a'.repeat(32)+'@quantic',quorumPin:'a'.repeat(64)};
const second={address:'bobby~'+'b'.repeat(32)+'@quantic',quorumPin:'b'.repeat(64)};
const binaryBytes=Buffer.from('synthetic-native-binary-for-mock-only');
const opts={root:dir,binary,binarySha256:hash(binaryBytes),first,second};
const pair=()=>twoPartyWindowsPlan(opts);
function publicResult(address){
 const sign=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const encrypt=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const describe=key=>{
  const j=key.publicKey.export({format:'jwk'});
  const p=Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]);
  return{point:p.toString('base64url'),pin:hash(key.publicKey.export({format:'der',type:'spki'})),jwk:j};
 };
 const s=describe(sign),e=describe(encrypt);
 const kem=generateKeyPairSync('ml-kem-768').publicKey.export({format:'der',type:'spki'});
 const dsa=generateKeyPairSync('ml-dsa-65').publicKey.export({format:'der',type:'spki'});
 assert.equal(kem.length,1206);assert.equal(dsa.length,1974);
 return{backend:'windows-software-pq-storage-lab',status:'local-provision-only-not-enrolled',address,
  deviceId:deviceIdForPublicKeyNode(e.jwk,32),
  signing:s.point,encryption:e.point,signingPin:s.pin,encryptionPin:e.pin,
  kemPublic:kem.toString('base64url'),dsaPublic:dsa.toString('base64url'),
  kemPin:hash(kem),dsaPin:hash(dsa),controllerPublic:randomBytes(32).toString('base64url')};
}
test('two-party plan cannot accept duplicate, malformed or nonlocal identities',()=>{
 const plan=pair();
 assert.deepEqual(plan.participants.map(x=>x.dir),[dir+'\\participant-a',dir+'\\participant-b']);
 for(const params of [
  {...opts,second:first},
  {...opts,first:{...first,quorumPin:'0'}},
  {...opts,root:'\\\\server\\share'},
  {...opts,root:'C:\\QuanticLab\\Pair\\..\\Pair'},
  {...opts,binarySha256:'badsum'}
 ])assert.throws(()=>twoPartyWindowsPlan(params));
});
test('preflight verifies independently pinned native executable and both vault directories are unused',async()=>{
 let misses=[];
 const fake={
  read:async path=>{assert.equal(path,binary);return Buffer.from(binaryBytes);},
  inspect:async path=>path===dir?{isDirectory:()=>true}:{isFile:()=>true,size:binaryBytes.length},
  missing:async path=>{misses.push(path);}
 };
 assert.equal(await checkTwoPartyWindowsPlan(pair(),fake),true);
 assert.deepEqual(misses,[dir+'\\participant-a',dir+'\\participant-b']);
 await assert.rejects(checkTwoPartyWindowsPlan(twoPartyWindowsPlan({...opts,binarySha256:'f'.repeat(64)}),fake));
 await assert.rejects(checkTwoPartyWindowsPlan(pair(),{
  ...fake,missing:async()=>{throw Error('existing vault');}
 }),/existing vault/);
});
test('two native key generations are independently validated and never treated as remote enrollment',async()=>{
 const output=[],steps=[];
 const result=await provisionTwoWindowsLab(pair(),{
  check:async()=>true,
  invoke:async(bin,path,pin,address)=>{
   steps.push({bin,path,pin,address});
   return publicResult(address);
  },
  afterEach:async(index,record)=>output.push({index,address:record.address})
 });
 assert.equal(result.status,'two-local-synthetic-vaults-provisioned');
 assert.equal(result.labOnly,true);
 assert.equal(result.remoteAuthoritiesConfigured,false);
 assert.equal(result.nativeMailRelayConfigured,false);
 assert.equal(result.liveAccountEnrollmentAuthorized,false);
 assert.equal(result.legacyDeletionAuthorized,false);
 assert.equal(result.participants.length,2);
 assert.notEqual(result.participants[0].deviceId,result.participants[1].deviceId);
 assert.deepEqual(steps.map(x=>x.path),[dir+'\\participant-a',dir+'\\participant-b']);
 assert.deepEqual(steps.map(x=>x.pin),[first.quorumPin,second.quorumPin]);
 assert.deepEqual(output,[{index:1,address:first.address},{index:2,address:second.address}]);
 assert.equal(JSON.stringify(result).includes('kemPublic'),false,'do not export arbitrary internal PQ key blobs');
});
test('substituted native result, wrong PQ digest and wrong device ID block the second identity',async()=>{
 for(const alter of [
  x=>({...x,address:second.address}),
  x=>({...x,kemPin:'0'.repeat(64)}),
  x=>({...x,kemPublic:Buffer.alloc(1206).toString('base64url'),kemPin:hash(Buffer.alloc(1206))}),
  x=>({...x,deviceId:'d-'+'0'.repeat(32)}),
  x=>({...x,signingPin:'0'.repeat(64)}),
  x=>({...x,controllerPublic:'x'}),
 ]) {
  let invoked=0;
  await assert.rejects(provisionTwoWindowsLab(pair(),{
   check:async()=>true,
   invoke:async(_,__,___,address)=>{invoked++;return alter(publicResult(address));}
  }));
  assert.equal(invoked,1,'never create participant B after participant A validation failed');
 }
});
test('failed second native generation never reports pair completed or retries over the first',async()=>{
 let invoked=0;
 await assert.rejects(provisionTwoWindowsLab(pair(),{
  check:async()=>true,
  invoke:async(_,__,___,address)=>{
   invoked++;
   if(invoked===2)throw Error('synthetic second vault refused');
   return publicResult(address);
  }
 }),/synthetic second vault refused/);
 assert.equal(invoked,2);
});
