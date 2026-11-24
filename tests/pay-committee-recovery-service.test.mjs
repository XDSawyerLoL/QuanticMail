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
import {COMMITTEE_TRANSFER_MAX,ROUND_TRANSFER_MAX} from '../lib/quantic/pay-round-transfer.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
for(const size of [16,31])for(const native of [false,true])test(size+' member certified recovery through '+(native?'native Scattering UDP':'local HTTP'),{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:300000},async()=>{
 const root=realpathSync(mkdtempSync(join(tmpdir(),'pay-committee-recovery-')));let proc,link,epoch=0;
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:size},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network,quorum=lab.committee.quorum,now=Date.now();
 const intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
 const draft={proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}],admissionTime:now};
 function certify(c,value){
  const v=createPayRoundLab(c),scope=v.scope,round=0;
  const nodes=witnesses.slice(0,quorum).map((w,i)=>v.openAuthority({authorityPin:config.witnesses[i].pin,classicalPrivateKey:w.cl.privateKey,pqPrivateKey:w.pq.privateKey}));
  const prepared={scope,round,value,votes:nodes.map(n=>n.prepare({round,value}))};
  const commit={scope,round,value,votes:nodes.map(n=>n.commit(prepared))};
  return {prepared,commit};
 }
 const admission={...draft,admissionCertificate:certify(lab.admissionRoundConfig([]),lab.draft([],draft).scope)};
 const info=lab.admit([],admission),certificate=certify(info.config,info.candidates[0].value),record={admission,certificate};
 const expected=lab.receipt([],record),bytes=Buffer.byteLength(JSON.stringify(record));
 assert.ok(bytes>ROUND_TRANSFER_MAX&&bytes<COMMITTEE_TRANSFER_MAX);
 const w=witnesses[size-1],p=await port(),token=randomBytes(32).toString('hex'),file=join(root,'config.json'),keyFile=join(root,'key.pem'),pqKeyFile=join(root,'pq.pem');
 async function renew(){
  await link?.close();
  if(native)link=await startNativeScatteringLink({dir:join(root,'epoch-'+(++epoch)),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:p,profile:'pay-committee-recovery-lab'});
  return createPayReplicaCarrier({loopbackPort:native?Number(new URL(link.url).port):p,token,network,committeeMode:true});
 }
 try{
  writeFileSync(keyFile,w.cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(pqKeyFile,w.pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(file,JSON.stringify({simulationOnly:true,directory:join(root,'store'),chainConfig:config,expectedNetwork:network,authorityKeyFile:keyFile,authorityPin:config.witnesses[size-1].pin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[size-1].pqPin,token,port:p}),{mode:0o600,flag:'wx'});
  execFileSync(process.execPath,[script,'provision',file],{stdio:'ignore'});
  proc=spawn(process.execPath,[script,'serve',file],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const t=setTimeout(()=>rej(Error('startup deadline')),10000);proc.once('error',e=>{clearTimeout(t);rej(e)});proc.once('exit',()=>{clearTimeout(t);rej(Error('witness stopped'))});proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY REPLICA LAB')){clearTimeout(t);res();}});proc.stderr.resume();});
  let client=await renew();assert.equal((await client.status()).sequence,0);
  await assert.rejects(client.prepare({scope:info.scope,input:{round:0,value:info.candidates[0].value}}));
  assert.deepEqual(await client.learn(record),expected);
  assert.equal((await client.status()).root,expected.root);
  client=await renew();
  assert.deepEqual(await client.record(1),record);
  assert.equal((await client.status()).totalCents,10000);
 }finally{await link?.close();if(proc&&proc.exitCode===null&&proc.signalCode===null)await new Promise(r=>{proc.once('exit',r);proc.kill();});rmSync(root,{recursive:true,force:true});}
});
