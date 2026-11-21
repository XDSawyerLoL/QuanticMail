import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,rmSync,cpSync,chmodSync,writeFileSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {openPayRoundReplica} from '../lib/quantic/pay-round-replica.mjs';
import {openAnchoredPayReplica} from '../lib/quantic/pay-anchored-replica.mjs';
import {createPayAnchorClient} from '../lib/quantic/pay-anchor-client.mjs';
import {createPayAnchorQuorum} from '../lib/quantic/pay-anchor-quorum.mjs';
const script=fileURLToPath(new URL('../scripts/serve-pay-anchor-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function restore(src,dst){cpSync(src,dst,{recursive:true});function fix(p){chmodSync(p,0o700);for(const e of readdirSync(p,{withFileTypes:true})){const q=join(p,e.name);if(e.isDirectory())fix(q);else chmodSync(q,0o600);}}fix(dst);}
test('three of four real TLS anchors protect a settled balance against restoring genesis',{skip:process.platform!=='linux',timeout:120000},async t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-anchor-quorum-'))),wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:4},()=>pair('ed25519')),members=[];
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network,authorityPin=config.witnesses[0].pin,now=1000000;
 const opts={directory:join(dir,'replica'),config,authorityPin,classicalPrivateKey:witnesses[0].cl.privateKey,pqPrivateKey:witnesses[0].pq.privateKey,clock:()=>now};
 const quorumFile=join(dir,'quorum.json');
 let node;
 function privateJSON(p,c){writeFileSync(p,JSON.stringify(c),{mode:0o600,flag:'wx'});}
 async function start(m){
  m.proc=spawn(process.execPath,[script,'serve',m.serverFile],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('anchor startup timeout')),10000);m.proc.once('error',e=>{clearTimeout(timer);rej(e);});m.proc.once('exit',()=>{clearTimeout(timer);rej(Error('anchor stopped'));});m.proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY ANCHOR LAB')){clearTimeout(timer);res();}});m.proc.stderr.resume();});
 }
 async function stop(m){if(m.proc&&m.proc.exitCode===null&&m.proc.signalCode===null)await new Promise(r=>{m.proc.once('exit',r);m.proc.kill();});}
 const quorum=()=>createPayAnchorQuorum({configFile:quorumFile,network,authorityPin});
 function certificateFor(roundLab,value){
  const authorities=[1,2,3].map(i=>roundLab.openAuthority({authorityPin:config.witnesses[i].pin,classicalPrivateKey:witnesses[i].cl.privateKey,pqPrivateKey:witnesses[i].pq.privateKey}));
  const prepared={scope:roundLab.scope,round:0,value,votes:authorities.map(a=>a.prepare({round:0,value}))};
  const commit={scope:roundLab.scope,round:0,value,votes:authorities.map(a=>a.commit(prepared))};
  return {prepared,commit};
 }
 try{
  node=openPayRoundReplica({...opts,createNew:true});const initial=node.checkpoint();node.close();
  restore(opts.directory,join(dir,'backup'));
  for(let i=0;i<4;i++){
   const serverFile=join(dir,'anchor-'+i+'.json'),clientFile=join(dir,'client-'+i+'.json'),keyFile=join(dir,'key-'+i+'.pem'),certFile=join(dir,'cert-'+i+'.pem'),p=await port(),token=randomBytes(32).toString('hex');
   execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',certFile,'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});chmodSync(keyFile,0o600);chmodSync(certFile,0o600);
   privateJSON(serverFile,{simulationOnly:true,directory:join(dir,'anchor-'+i),initial,port:p,token,keyFile,certFile});
   privateJSON(clientFile,{simulationOnly:true,network,authorityPin,port:p,token,certFile});
   execFileSync(process.execPath,[script,'provision',serverFile],{stdio:'ignore'});
   const m={serverFile,clientFile};members.push(m);await start(m);
  }
  privateJSON(quorumFile,{simulationOnly:true,network,authorityPin,members:members.map(m=>m.clientFile)});
  const badFile=join(dir,'duplicate.json');privateJSON(badFile,{simulationOnly:true,network,authorityPin,members:[...members.slice(0,3).map(m=>m.clientFile),members[0].clientFile]});
  assert.throws(()=>createPayAnchorQuorum({configFile:badFile,network,authorityPin}));
  const q=quorum();assert.deepEqual(q.read(),initial);
  await stop(members[3]);
  node=openAnchoredPayReplica({...opts,anchor:q});
  const intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={admissionTime:now,proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}]};
  const a=createPayRoundLab(lab.admissionRoundConfig([])),av=lab.draft([],draft).scope;
  const admission={...draft,admissionCertificate:certificateFor(a,av)},info=lab.admit([],admission);
  const b=createPayRoundLab(info.config),record={admission,certificate:certificateFor(b,info.candidates[0].value)};
  const receipt=lab.receipt([],record);
  assert.deepEqual(node.learn(record),receipt);
  assert.deepEqual(node.status().balances,{'demo-alice':2500,'demo-bob':7500});
  const latest=node.checkpoint();assert.equal(latest.sequence,1);node.close();
  await start(members[3]);
  const stale=createPayAnchorClient({configFile:members[3].clientFile,network,authorityPin});
  assert.deepEqual(stale.read(),initial);assert.deepEqual(quorum().read(),latest);
  // Two current anchors plus one stale must not be counted as three.
  await stop(members[2]);const blocked=quorum();assert.throws(()=>blocked.read(),/quorum halted/);assert.equal(blocked.status().halted,true);
  await start(members[2]);assert.deepEqual(quorum().read(),latest);
  for(const m of members.slice(0,3)){
   const x=createPayAnchorClient({configFile:m.clientFile,network,authorityPin});
   assert.deepEqual(x.read(),latest);assert.throws(()=>x.compareAndSwap(latest,initial));
  }
  rmSync(opts.directory,{recursive:true,force:true});restore(join(dir,'backup'),opts.directory);
  assert.throws(()=>openAnchoredPayReplica({...opts,anchor:quorum()}),/checkpoint mismatch/);
  t.diagnostic('3 independent TLS services retain settled checkpoint, 1 stale, 2 current insufficient, old 100 EUR snapshot rejected');
 }finally{node?.close();await Promise.all(members.map(stop));rmSync(dir,{recursive:true,force:true});}
});
