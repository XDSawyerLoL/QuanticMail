import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {collectCommitteeVotes} from '../lib/quantic/pay-committee-quorum.mjs';
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('./helpers/pay-synthetic-wrong-vote-service.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.export({format:'der',type:'spki'});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const native of [false,true])test('five independent wrong-vote services cannot inflate a 10-signature quorum over '+(native?'native UDP':'HTTP'),{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_COMMITTEE_DISTRIBUTED_TEST),timeout:120000},async()=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-byzantine-net-'))),processes=[],links=[];
 const network='a'.repeat(64),value='c'.repeat(64),wrong='d'.repeat(64);
 const keys=Array.from({length:16},()=>{
  const cl=generateKeyPairSync('ed25519'),pq=generateKeyPairSync('ml-dsa-65'),a=spki(cl.publicKey),b=spki(pq.publicKey);
  const pub={pin:sha(a),pqPin:sha(b),publicKey:a.toString('base64url'),pqPublicKey:b.toString('base64url')};
  return {pub,credentials:{authorityPin:pub.pin,classicalPrivateKey:cl.privateKey,pqPrivateKey:pq.privateKey}};
 });
 const lab=createPayRoundLab({network,height:1,previousRoot:'b'.repeat(64),authorities:keys.map(k=>k.pub),committeeMode:true,admissionRound:true});
 const honest=keys.slice(0,11).map(k=>({authorityPin:k.pub.pin,client:{prepare:async()=>lab.openAuthority(k.credentials).prepare({round:0,value})}}));
 const bad=[];
 try{
  for(let i=11;i<16;i++){
   const k=keys[i],vote=lab.openAuthority(k.credentials).prepare({round:0,value:wrong});
   assert.doesNotThrow(()=>lab.inspectOutput('prepare',{round:0,value:wrong},vote,k.pub.pin));
   const p=await port(),token=randomBytes(32).toString('hex'),file=join(dir,'fixture-'+i+'.json');
   writeFileSync(file,JSON.stringify({simulationOnly:true,network,port:p,token,vote}),{mode:0o600,flag:'wx'});
   const child=spawn(process.execPath,[script,file],{stdio:['ignore','pipe','pipe']});processes.push(child);
   await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('fixture startup')),10000);child.once('error',e=>{clearTimeout(timer);rej(e)});child.once('exit',()=>{clearTimeout(timer);rej(Error('fixture stopped'))});child.stdout.on('data',b=>{if(b.toString().includes('READY SYNTHETIC WRONG VOTE')){clearTimeout(timer);res();}});child.stderr.resume();});
   let loopbackPort=p;
   if(native){const l=await startNativeScatteringLink({dir:join(dir,'link-'+i),binary:resolve(process.env.QUANTIC_PAY_COMMITTEE_DISTRIBUTED_TEST),relayPort:p,profile:'pay-committee-vote-lab'});links.push(l);loopbackPort=Number(new URL(l.url).port);}
   bad.push({authorityPin:k.pub.pin,client:createPayReplicaCarrier({loopbackPort,token,network,committeeMode:true,voting:true})});
  }
  // Prove that all five actually answered over the selected network path,
  // rather than counting a transport outage as an adversarial rejection.
  const returned=await Promise.all(bad.map(({client})=>client.prepare({scope:lab.scope,input:{round:0,value}})));
  returned.forEach((v,i)=>{lab.inspectOutput('prepare',{round:0,value:wrong},v,bad[i].authorityPin);assert.throws(()=>lab.inspectOutput('prepare',{round:0,value},v,bad[i].authorityPin));});
  const collect=authorities=>collectCommitteeVotes({lab,authorities,phase:'prepare',round:0,value,invoke:c=>c.prepare({scope:lab.scope,input:{round:0,value}})});
  await assert.rejects(collect([...honest.slice(0,10),...bad]));
  const q=await collect([...honest,...bad]);assert.equal(q.votes.length,11);assert.deepEqual(q.votes.map(v=>v.pin),honest.map(v=>v.authorityPin));
 }finally{
  await Promise.all(links.map(l=>l.close()));
  await Promise.all(processes.map(p=>p.exitCode!==null||p.signalCode!==null?Promise.resolve():new Promise(r=>{p.once('exit',r);p.kill();})));
  rmSync(dir,{recursive:true,force:true});
 }
});
