import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {compactPayView} from '../lib/quantic/pay-compact-view.mjs';
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
import {createCommitteeSession} from '../lib/quantic/pay-committee-session.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const native of [false,true])test('16 member admission and financial quorum includes independent persistent '+(native?'native UDP':'HTTP')+' voter',{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:300000},async t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-committee-vote-')));let proc,link,epoch=0;
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:16},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network;
 const p=await port(),token=randomBytes(32).toString('hex'),file=join(dir,'config.json'),keyFile=join(dir,'key.pem'),pqKeyFile=join(dir,'pq.pem'),w=witnesses[0];
 const credentials=i=>({authorityPin:config.witnesses[i].pin,classicalPrivateKey:witnesses[i].cl.privateKey,pqPrivateKey:witnesses[i].pq.privateKey});
 async function start(){
  proc=spawn(process.execPath,[script,'serve',file],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const t=setTimeout(()=>rej(Error('startup deadline')),10000);proc.once('error',e=>{clearTimeout(t);rej(e)});proc.once('exit',()=>{clearTimeout(t);rej(Error('witness stopped'))});proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY REPLICA LAB')){clearTimeout(t);res();}});proc.stderr.resume();});
 }
 async function stop(){if(proc&&proc.exitCode===null&&proc.signalCode===null)await new Promise(r=>{proc.once('exit',r);proc.kill();});}
 async function renew(voting=true){
  await link?.close();
  if(native)link=await startNativeScatteringLink({dir:join(dir,'epoch-'+(++epoch)),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:p,profile:voting?'pay-committee-vote-lab':'pay-committee-recovery-lab'});
  return createPayReplicaCarrier({loopbackPort:native?Number(new URL(link.url).port):p,token,network,committeeMode:true,voting});
 }
 try{
  writeFileSync(keyFile,w.cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(pqKeyFile,w.pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(dir,'store'),chainConfig:config,expectedNetwork:network,authorityKeyFile:keyFile,authorityPin:config.witnesses[0].pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[0].pqPin,token,port:p}),{mode:0o600,flag:'wx'});
  execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});await start();
  let client=await renew();
  const now=Date.now(),intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}],admissionTime:now};
  const a=createPayRoundLab(lab.admissionRoundConfig([])),scope=a.scope,value=lab.draft([],draft).scope;
  const others=Array.from({length:10},(_,i)=>a.openAuthority(credentials(i+1)));
  t.diagnostic('admission prepare started');
  const remote=await client.admissionPrepare({scope,input:{draft,round:0}});
  await stop();await start();
  assert.deepEqual(await client.admissionPrepare({scope,input:{draft,round:0}}),remote);
  const prepared={scope,round:0,value,votes:[remote,...others.map(n=>n.prepare({round:0,value}))]};
  assert.throws(()=>a.prepared({...prepared,votes:prepared.votes.slice(1)}));
  t.diagnostic('admission commit begins at age ms='+String(Date.now()-now));
  const c={scope,round:0,value,votes:[await client.admissionCommit({scope,input:{draft,certificate:prepared}}),...others.map(n=>n.commit(prepared))]};
  const admission={...draft,admissionCertificate:{prepared,commit:c}},info=lab.admit([],admission);
  // No fake clock: new prepare is limited to intake; certified completion
  // must still occur before the original payer expiry.
  client=await renew();
  t.diagnostic('admission installation begins at age ms='+String(Date.now()-now));
  await client.admit(admission);
  t.diagnostic('admission installed at age ms='+String(Date.now()-now));
  const b=createPayRoundLab(info.config),fscope=b.scope,fvalue=info.candidates[0].value;
  const members=Array.from({length:10},(_,i)=>b.openAuthority(credentials(i+1)));
  const first={scope:fscope,round:0,value:fvalue,votes:[await client.prepare({scope:fscope,input:{round:0,value:fvalue}}),...members.map(n=>n.prepare({round:0,value:fvalue}))]};
  await client.commitVote({scope:fscope,input:first});for(const n of members)n.commit(first);
  client=await renew();
  const report=await client.changeView({scope:fscope,input:1});
  const view=compactPayView({scope:fscope,round:1,reports:[report,...members.map(n=>n.changeView(1))]},16);
  assert.equal(b.selectView(view).requiredValue,fvalue);
  // Renew automatically before each logical operation, never after failure.
  await link?.close();link=null;
  const pinnedPort=p;
  const session=createCommitteeSession({network,authorityPin:config.witnesses[0].pin,provision:async p=>{
   const l=native?await startNativeScatteringLink({dir:join(dir,'epoch-'+(++epoch)),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:pinnedPort,profile:p.profile==='vote'?'pay-committee-vote-lab':'pay-committee-recovery-lab'}):null;
   return {network,authorityPin:config.witnesses[0].pin,profile:p.profile,epochId:l?.epochId??randomBytes(32).toString('hex'),loopbackPort:l?Number(new URL(l.url).port):pinnedPort,token,close:async()=>{await l?.close();}};
  }});
  client=session;
  const fp={scope:fscope,round:1,value:fvalue,votes:[await client.prepare({scope:fscope,input:{round:1,value:fvalue,viewCertificate:view}}),...members.map(n=>n.prepare({round:1,value:fvalue,viewCertificate:view}))]};
  const fc={scope:fscope,round:1,value:fvalue,votes:[await client.commitVote({scope:fscope,input:fp}),...members.map(n=>n.commit(fp))]};
  const record={admission,certificate:{prepared:fp,commit:fc}},receipt=lab.receipt([],record);
  assert.deepEqual(await client.learn(record),receipt);
  assert.equal((await client.status()).root,receipt.root);
  assert.equal(session.sessionStatus().epochsConsumed,4);
  session.close();
 }finally{await link?.close();await stop();rmSync(dir,{recursive:true,force:true});}
});
