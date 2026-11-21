// Laboratory only. Four independent witnesses are simulated by local files.
import {randomBytes,createPublicKey,sign,verify} from 'node:crypto';
import {openSync,closeSync,readFileSync,writeFileSync,fsyncSync,renameSync,unlinkSync} from 'node:fs';
import {dirname} from 'node:path';
import {assertVerifiedManifest} from '../quantic/manifest-node.mjs';
import {mergeManifestState} from '../quantic/manifest-core.mjs';
import {pin,manifestDigest} from './scattering-manifest-session.mjs';
const DOMAIN='quantic-scattering-witness-lab-v1', TTL=10000;
const check=(v,m)=>{if(!v)throw Error(m)};
const hex=(s,n)=>typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);
const root=m=>pin(createPublicKey({key:m.payload.identitySigningPublicKey,format:'jwk'}));
const body=p=>Buffer.from(JSON.stringify([DOMAIN,p.witness,p.challenge,p.address,p.sequence,p.digest,p.issued,p.expires]));
function checked(m,address,rootPin){assertVerifiedManifest(m);check(m.payload.canonicalAddress===address&&m.payload.fingerprint.length===32&&root(m)===rootPin,'identity pin mismatch');return m;}
function flushDir(path){if(process.platform==='win32')return;const fd=openSync(dirname(path),'r');try{fsyncSync(fd)}finally{closeSync(fd)}}
function writeExclusive(path,m){const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,JSON.stringify(m));fsyncSync(fd)}finally{closeSync(fd)}}
export function provisionWitnessState(path,manifest,address,rootPin){checked(manifest,address,rootPin);writeExclusive(path,manifest);flushDir(path);}
// Single writer per witness. Deployment must enforce independent custody and durable storage.
export function openWitness({path,address,rootPin,privateKey,clock=Date.now,labOnly}){
  check(labOnly===true,'lab only');check(privateKey.asymmetricKeyType==='ed25519','invalid witness key');
  const witness=pin(createPublicKey(privateKey));
  const load=()=>checked(JSON.parse(readFileSync(path,'utf8')),address,rootPin);
  let high=load();
  function current(){const disk=load();high=mergeManifestState(high,disk);return high;}
  return {witness,
    advance(m){m=checked(m,address,rootPin);const old=current();const next=mergeManifestState(old,m);
      const active=new Set(next.payload.devices.map(d=>d.deviceId)),revoked=new Set(next.payload.revocations.map(d=>d.deviceId));
      for(const d of old.payload.devices)check(active.has(d.deviceId)||revoked.has(d.deviceId),'removed without revocation');
      if(next!==old){const tmp=path+'.'+randomBytes(12).toString('hex')+'.tmp';try{writeExclusive(tmp,next);renameSync(tmp,path);flushDir(path)}finally{try{unlinkSync(tmp)}catch(e){if(e.code!=='ENOENT')throw e}}high=next;}
      return {sequence:high.payload.sequence,digest:manifestDigest(high)};
    },
    attest(request){check(request?.address===address&&hex(request.challenge,64),'invalid challenge');const m=current(),issued=clock();check(Number.isSafeInteger(issued),'invalid clock');const proof={witness,challenge:request.challenge,address,sequence:m.payload.sequence,digest:manifestDigest(m),issued,expires:issued+TTL};return {manifest:structuredClone(m),proof,signature:sign(null,body(proof),privateKey).toString('hex')};}
  };
}
export function createWitnessReader({address,rootPin,witnessKeys,query,clock=Date.now,labOnly}){
  check(labOnly===true&&Array.isArray(witnessKeys)&&witnessKeys.length===4,'four lab witnesses required');
  const keys=new Map(witnessKeys.map(k=>{check(k.type==='public'&&k.asymmetricKeyType==='ed25519','invalid witness key');return [pin(k),k]}));check(keys.size===4,'distinct witness keys required');
  let high=null,last=-Infinity;
  return function read(requestedAddress){
    const start=clock();check(Number.isSafeInteger(start)&&start>=last&&requestedAddress===address,'clock rollback or identity mismatch');last=start;
    const challenge=randomBytes(32).toString('hex'),request={address,challenge};const answers=query(Object.freeze(request));
    const now=clock();check(Number.isSafeInteger(now)&&now>=start&&now-start<TTL,'challenge expired');last=now;
    check(Array.isArray(answers)&&answers.length<=16,'invalid witness replies');const bySigner=new Map(),equivocal=new Set();
    for(const item of answers){try{const p=item.proof,k=keys.get(p.witness);check(k&&p.address===address&&p.challenge===challenge,'wrong witness or challenge');check(Number.isSafeInteger(p.issued)&&Number.isSafeInteger(p.expires)&&p.issued>=start-1000&&p.issued<=now+1000&&p.expires===p.issued+TTL&&p.expires>now,'stale proof');check(hex(item.signature,128)&&verify(null,body(p),k,Buffer.from(item.signature,'hex')),'invalid signature');const m=checked(item.manifest,address,rootPin);check(p.sequence===m.payload.sequence&&p.digest===manifestDigest(m),'wrong manifest digest');const id=p.sequence+':'+p.digest,old=bySigner.get(p.witness);if(old&&old.id!==id)equivocal.add(p.witness);else if(!old)bySigner.set(p.witness,{id,m,proof:p});}catch{/* Invalid replies cannot contribute to quorum. */}}
    const groups=new Map();for(const [name,r] of bySigner){if(equivocal.has(name))continue;const g=groups.get(r.id)??[];g.push(r);groups.set(r.id,g)}
    const agreed=[...groups.values()].filter(g=>g.length>=3);check(agreed.length===1,'no fresh 3-of-4 quorum');const g=agreed[0],m=g[0].m;
    high=mergeManifestState(high,m);return {manifest:structuredClone(high),sequence:high.payload.sequence,digest:manifestDigest(high),validUntil:Math.min(...g.map(r=>r.proof.expires))};
  };
}
