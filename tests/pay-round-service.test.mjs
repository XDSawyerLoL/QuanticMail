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
import {openRoundChain} from '../lib/quantic/pay-round-chain-store.mjs';
import {createPayRoundCarrier} from '../lib/quantic/pay-round-carrier.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-round-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const useCarrier of [false,true])test('four financial round authorities resolve 2-2 prepare split after restart '+(useCarrier?'over native Scattering UDP':'over local HTTP'),{skip:process.platform!=='linux'||(useCarrier&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:240000},async()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-round-service-'))),nodes=[],links=[],now=1000000;
 const ids=['demo-alice','demo-bob','demo-shop'],wallets=ids.map(()=>pair('ec')),witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={wallets:ids.map((id,i)=>({id,initialCents:i===0?10000:0,...pub(wallets[i])})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config);
 let chain;
 function proposal(payee){
  const intent=lab.prepare([],{payer:ids[0],payee,cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent),k=wallets[0];
  return {intent,signature:sign('sha256',raw,{key:k.cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,k.pq.privateKey).toString('base64url')};
 }
 async function start(n){
  n.proc=spawn(process.execPath,[script,'serve',n.file],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const t=setTimeout(()=>rej(Error('startup deadline')),10000);n.proc.once('error',e=>{clearTimeout(t);rej(e)});n.proc.once('exit',()=>{clearTimeout(t);rej(Error('witness stopped'))});n.proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY ROUND LAB')){clearTimeout(t);res();}});n.proc.stderr.resume();});
 }
 async function stop(n){if(!n.proc||n.proc.exitCode!==null||n.proc.signalCode!==null)return;await new Promise(r=>{n.proc.once('exit',r);n.proc.kill();});}
 try{
  chain=openRoundChain({directory:join(root,'chain'),config,createNew:true,clock:()=>now});
  const proposals=[proposal(ids[1]),proposal(ids[2])],info=chain.admit(proposals),[a,b]=info.candidates.map(c=>c.value),verifier=createPayRoundLab(info.config);
  for(let i=0;i<4;i++){
   const k=witnesses[i],p=await port(),token=randomBytes(32).toString('hex'),file=join(root,'config-'+i+'.json'),keyFile=join(root,'key-'+i+'.pem'),pqKeyFile=join(root,'pq-'+i+'.pem');
   writeFileSync(keyFile,k.cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(pqKeyFile,k.pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
   writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(root,'store-'+i),chainConfig:config,records:[],admission:{proposals,admissionTime:now},expectedScope:info.scope,authorityKeyFile:keyFile,authorityPin:config.witnesses[i].pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[i].pqPin,token,port:p}),{mode:0o600,flag:'wx'});
   const n={file,p,token};nodes.push(n);execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});await start(n);
  }
  if(useCarrier)for(let i=0;i<4;i++)links.push(await startNativeScatteringLink({dir:join(root,'link-'+i),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:nodes[i].p,profile:'pay-round-lab'}));
  const clients=nodes.map((n,i)=>createPayRoundCarrier({loopbackPort:useCarrier?Number(new URL(links[i].url).port):n.p,token:n.token,scope:info.scope}));
  const old=await Promise.all(clients.map((c,i)=>c.prepare({round:0,value:i<2?a:b})));
  assert.throws(()=>verifier.prepared({scope:info.scope,round:0,value:a,votes:old.slice(0,2)}));
  await Promise.all(nodes.map(stop));await Promise.all(nodes.map(start));
  await assert.rejects(clients[0].prepare({round:0,value:b}));
  const reports=await Promise.all(clients.map(c=>c.changeView(1)));
  const viewCertificate={scope:info.scope,round:1,reports:reports.slice(0,3)};
  assert.equal(verifier.selectView(viewCertificate).requiredValue,null);
  const p={scope:info.scope,round:1,value:b,votes:await Promise.all(clients.slice(0,3).map(c=>c.prepare({round:1,value:b,viewCertificate})))};
  const commit={scope:info.scope,round:1,value:b,votes:await Promise.all(clients.slice(0,3).map(c=>c.commit(p)))};
  // Hide the first final certificate. Three retained prepared claims now
  // exceed one 32 KiB carrier frame, and must force the same financial value.
  const claims=await Promise.all(clients.map(c=>c.changeView(2)));
  const complex={scope:info.scope,round:2,reports:claims.slice(0,3)};
  assert.ok(Buffer.byteLength(JSON.stringify(complex))>32768);
  assert.equal(verifier.selectView(complex).requiredValue,b);
  const next={scope:info.scope,round:2,value:b,votes:await Promise.all(clients.slice(0,3).map(c=>c.prepare({round:2,value:b,viewCertificate:complex})))};
  const nextCommit={scope:info.scope,round:2,value:b,votes:await Promise.all(clients.slice(0,3).map(c=>c.commit(next)))};
  const certificate={prepared:next,commit:nextCommit};
  assert.throws(()=>chain.commit({prepared:next,commit:{...nextCommit,votes:nextCommit.votes.slice(0,2)}}));
  const result=chain.commit(certificate);assert.equal(result.payee,ids[2]);assert.equal(result.realPaymentAuthorized,false);
  await Promise.all(clients.map(c=>c.learn(certificate)));
  assert.deepEqual(chain.snapshot().balances,{'demo-alice':2500,'demo-bob':0,'demo-shop':7500});
  assert.equal(chain.snapshot().totalCents,10000);
  assert.deepEqual(await clients[3].status().then(x=>x.finalValue),b);
 }finally{chain?.close();await Promise.all(links.map(x=>x.close()));await Promise.all(nodes.map(stop));rmSync(root,{recursive:true,force:true});}
});
