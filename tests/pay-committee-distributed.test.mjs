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
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
import {collectCommitteeVotes} from '../lib/quantic/pay-committee-quorum.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const native of [false,true])test('16 separately provisioned processes, five unavailable, 11-vote quorum and certified rejoin over '+(native?'native UDP':'HTTP'),{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_COMMITTEE_DISTRIBUTED_TEST),timeout:600000},async t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-distributed-'))),nodes=[],links=new Map();let epoch=0;
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:16},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network;
 const live=Array.from({length:11},(_,i)=>i),absent=[11,12,13,14,15];
 async function start(n){
  n.proc=spawn(process.execPath,[script,'serve',n.file],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('startup deadline '+n.i)),15000);n.proc.once('error',e=>{clearTimeout(timer);rej(e)});n.proc.once('exit',()=>{clearTimeout(timer);rej(Error('authority stopped '+n.i))});n.proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY REPLICA LAB')){clearTimeout(timer);res();}});n.proc.stderr.resume();});
 }
 async function stop(n){if(n.proc&&n.proc.exitCode===null&&n.proc.signalCode===null)await new Promise(r=>{n.proc.once('exit',r);n.proc.kill();});}
 async function closeLinks(){await Promise.all([...links.values()].map(l=>l.close()));links.clear();}
 async function renew(indices,voting){
  await closeLinks();epoch++;
  // Separate per-authority link and credentials. Fresh epochs, no auto retry.
  if(native){
   const binary=resolve(process.env.QUANTIC_PAY_COMMITTEE_DISTRIBUTED_TEST);
   const results=await Promise.allSettled(indices.map(async i=>{
    const l=await startNativeScatteringLink({dir:join(dir,'epoch-'+epoch+'-'+i),binary,relayPort:nodes[i].p,profile:voting?'pay-committee-vote-lab':'pay-committee-recovery-lab'});
    links.set(i,l);
   }));
   for(const r of results)if(r.status==='rejected')throw r.reason;
  }
  return indices.map(i=>({authorityPin:config.witnesses[i].pin,client:createPayReplicaCarrier({loopbackPort:native?Number(new URL(links.get(i).url).port):nodes[i].p,token:nodes[i].token,network,committeeMode:true,voting})}));
 }
 try{
  for(let i=0;i<16;i++){
   const w=witnesses[i],p=await port(),token=randomBytes(32).toString('hex'),file=join(dir,'config-'+i+'.json'),keyFile=join(dir,'key-'+i+'.pem'),pqKeyFile=join(dir,'pq-'+i+'.pem');
   writeFileSync(keyFile,w.cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(pqKeyFile,w.pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(dir,'store-'+i),chainConfig:config,expectedNetwork:network,authorityKeyFile:keyFile,authorityPin:config.witnesses[i].pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[i].pqPin,token,port:p}),{mode:0o600,flag:'wx'});
   execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});
   const node={i,p,token,file};nodes.push(node);await start(node);
  }
  await Promise.all(absent.map(i=>stop(nodes[i])));
  for(const i of absent)assert.notEqual(nodes[i].proc.exitCode??nodes[i].proc.signalCode,null);
  let peers=await renew(live,true);
  const now=Date.now(),intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={admissionTime:now,proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}]};
  const a=createPayRoundLab(lab.admissionRoundConfig([])),av=lab.draft([],draft).scope;
  // No authority's key is used to create a vote in this coordinator.
  await assert.rejects(collectCommitteeVotes({lab:a,authorities:peers.slice(0,10),phase:'prepare',round:0,value:av,invoke:()=>{throw Error('must not call');}}));
  const ap=await collectCommitteeVotes({lab:a,authorities:peers,phase:'prepare',round:0,value:av,invoke:c=>c.admissionPrepare({scope:a.scope,input:{draft,round:0}})});
  assert.throws(()=>a.prepared({...ap,votes:ap.votes.slice(0,10)}));
  const ac=await collectCommitteeVotes({lab:a,authorities:peers,phase:'commit',round:0,value:av,invoke:c=>c.admissionCommit({scope:a.scope,input:{draft,certificate:ap}})});
  const admission={...draft,admissionCertificate:{prepared:ap,commit:ac}},info=lab.admit([],admission);
  await Promise.all(peers.map(async ({client})=>assert.equal((await client.admit(admission)).scope,info.scope)));
  t.diagnostic('admission wall time ms='+String(Date.now()-now));
  const b=createPayRoundLab(info.config),value=info.candidates[0].value;
  const fp=await collectCommitteeVotes({lab:b,authorities:peers,phase:'prepare',round:0,value,invoke:c=>c.prepare({scope:b.scope,input:{round:0,value}})});
  const fc=await collectCommitteeVotes({lab:b,authorities:peers,phase:'commit',round:0,value,invoke:c=>c.commitVote({scope:b.scope,input:fp})});
  const record={admission,certificate:{prepared:fp,commit:fc}},receipt=lab.receipt([],record);
  peers=await renew(live,false);
  await Promise.all(peers.map(async ({client})=>assert.deepEqual(await client.learn(record),receipt)));
  for(const s of await Promise.all(peers.map(({client})=>client.status()))){assert.equal(s.sequence,1);assert.equal(s.root,receipt.root);}
  await closeLinks();
  await Promise.all(absent.map(i=>start(nodes[i])));
  // Retrieve the certified decision from a live authority, not from its private keys.
  const source=(await renew([0],false))[0].client;
  const recovered=await source.record(1);assert.deepEqual(recovered,record);
  peers=await renew(absent,false);
  for(const s of await Promise.all(peers.map(({client})=>client.status())))assert.equal(s.sequence,0);
  await Promise.all(peers.map(async ({client})=>assert.deepEqual(await client.learn(recovered),receipt)));
  for(const s of await Promise.all(peers.map(({client})=>client.status()))){assert.equal(s.sequence,1);assert.equal(s.root,receipt.root);assert.deepEqual(s.balances,{'demo-alice':2500,'demo-bob':7500});assert.equal(s.totalCents,10000);}
  t.diagnostic('16 authorities retained identical committed root, five recovered from peer');
 }finally{await closeLinks();await Promise.all(nodes.map(stop));rmSync(dir,{recursive:true,force:true});}
});
