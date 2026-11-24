import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
import {createPayReplicaCarrier} from '../lib/quantic/pay-replica-carrier.mjs';
import {synchronizePayReplica} from '../lib/quantic/pay-replica-sync.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const native of [false,true])test('permanent replica processes advance successive heights and catch up through '+(native?'native Scattering UDP':'local HTTP'),{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:240000},async()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-replica-service-'))),nodes=[],links=[];
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={admissionPolicy:'quorum-v1',wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 let chain,clients,epoch=0;
 async function start(n){
  n.proc=spawn(process.execPath,[script,'serve',n.file],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const t=setTimeout(()=>rej(Error('startup deadline')),10000);n.proc.once('error',e=>{clearTimeout(t);rej(e)});n.proc.once('exit',()=>{clearTimeout(t);rej(Error('witness stopped'))});n.proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY REPLICA LAB')){clearTimeout(t);res();}});n.proc.stderr.resume();});
 }
 async function stop(n){if(!n.proc||n.proc.exitCode!==null||n.proc.signalCode!==null)return;await new Promise(r=>{n.proc.once('exit',r);n.proc.kill();});}
 async function renew(){
  await Promise.all(links.splice(0).map(x=>x.close()));epoch++;
  if(native)for(let i=0;i<4;i++)links.push(await startNativeScatteringLink({dir:join(root,'epoch-'+epoch+'-link-'+i),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:nodes[i].p,profile:'pay-replica-lab'}));
  clients=nodes.map((n,i)=>createPayReplicaCarrier({loopbackPort:native?Number(new URL(links[i].url).port):n.p,token:n.token,network:chain.snapshot().network}));
 }
 function proposal(payer,payee,cents){
  const intent=chain.prepare({payer,payee,cents,nonce:randomBytes(32).toString('hex')}),raw=chain.transcript(intent),k=wallets[ids.indexOf(payer)];
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 async function settle(from,to,cents,active){
  const proof=proposal(from,to,cents),draft={proposals:[proof],admissionTime:Date.now()},members=active.map(i=>clients[i]);
  const endorsements=await Promise.all(members.map(c=>c.voteAdmission(draft)));
  assert.throws(()=>chain.admitExact({...draft,endorsements:endorsements.slice(0,2)}));
  const admission={...draft,endorsements};
  const {info}=chain.admitExact(admission),scope=info.scope,value=info.candidates[0].value;
  await Promise.all(members.map(async c=>assert.equal((await c.admit(admission)).scope,scope)));
  const p={scope,round:0,value,votes:await Promise.all(members.map(c=>c.prepare({scope,input:{round:0,value}})))};
  const commit={scope,round:0,value,votes:await Promise.all(members.map(c=>c.commitVote({scope,input:p})))};
  const record={admission,certificate:{prepared:p,commit}},receipt=chain.commit(record.certificate);
  await Promise.all(members.map(async c=>assert.deepEqual(await c.learn(record),receipt)));
  return record;
 }
 try{
  chain=openRoundChain({directory:join(root,'chain'),config,createNew:true});
  for(let i=0;i<4;i++){
   const k=witnesses[i],p=await port(),token=randomBytes(32).toString('hex'),file=join(root,'config-'+i+'.json'),keyFile=join(root,'key-'+i+'.pem'),pqKeyFile=join(root,'pq-'+i+'.pem');
   writeFileSync(keyFile,k.cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(pqKeyFile,k.pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(root,'store-'+i),chainConfig:config,expectedNetwork:chain.snapshot().network,authorityKeyFile:keyFile,authorityPin:config.witnesses[i].pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[i].pqPin,token,port:p}),{mode:0o600,flag:'wx'});
   const n={file,p,token};nodes.push(n);execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});await start(n);
  }
  await renew();await stop(nodes[3]);
  await settle(ids[0],ids[1],7500,[0,1,2]);
  await start(nodes[3]);await renew();
  assert.equal((await clients[3].status()).sequence,0);
  const sync=i=>synchronizePayReplica({network:chain.snapshot().network,targetPin:config.witnesses[i].pin,target:clients[i],peers:[0,1].map(j=>({authorityPin:config.witnesses[j].pin,client:clients[j]})),maxSteps:1});
  assert.equal((await sync(3)).applied,1);
  assert.equal((await clients[3].status()).root,chain.snapshot().root);
  // Catch-up and a full gated transfer consume separate bounded epochs.
  await renew();
  await stop(nodes[2]);
  await settle(ids[1],ids[2],7000,[0,1,3]);
  await start(nodes[2]);await renew();
  assert.equal((await sync(2)).applied,1);
  const states=await Promise.all(clients.map(c=>c.status()));
  for(const s of states){assert.equal(s.sequence,2);assert.equal(s.root,chain.snapshot().root);assert.deepEqual(s.balances,{'demo-alice':2500,'demo-bob':500,'demo-shop':7000});assert.equal(s.totalCents,10000);}
 }finally{chain?.close();await Promise.all(links.map(x=>x.close()));await Promise.all(nodes.map(stop));rmSync(root,{recursive:true,force:true});}
});
