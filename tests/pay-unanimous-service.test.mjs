// Strict end-to-end laboratory: one persistent remote voter with four real
// TLS anchor processes, fifteen in-memory independent signers. Same host only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {mkdtempSync,realpathSync,writeFileSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRoundCirculationLab} from '../lib/quantic/pay-circulation-lab.mjs';
import {createPayRoundLab} from '../lib/quantic/pay-round-lab.mjs';
import {createPayAnchorClient} from '../lib/quantic/pay-anchor-client.mjs';
import {createCommitteeSession} from '../lib/quantic/pay-committee-session.mjs';
import {startNativeScatteringLink} from './helpers/native-scattering-link.mjs';
const replicaScript=fileURLToPath(new URL('../scripts/serve-pay-replica-lab.mjs',import.meta.url));
const anchorScript=fileURLToPath(new URL('../scripts/serve-pay-anchor-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function privateJson(path,value){writeFileSync(path,JSON.stringify(value),{mode:0o600,flag:'wx'});}
async function stop(m){if(m?.proc&&m.proc.exitCode===null&&m.proc.signalCode===null)await new Promise(r=>{m.proc.once('exit',r);m.proc.kill();});}
async function start(m){
 m.proc=spawn(process.execPath,m.args,{stdio:['ignore','pipe','pipe']});
 await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('startup deadline: '+m.ready)),20000);m.proc.once('error',e=>{clearTimeout(timer);rej(e);});m.proc.once('exit',()=>{clearTimeout(timer);rej(Error('process stopped: '+m.ready));});m.proc.stdout.on('data',b=>{if(b.toString().includes(m.ready)){clearTimeout(timer);res();}});m.proc.stderr.resume();});
}
for(const native of [false,true])test('strict 16/16 payment and 4/4 external anchor guard through '+(native?'native UDP':'HTTP'),{skip:process.platform!=='linux'||(native&&!process.env.QUANTIC_PAY_SCATTERING_TEST),timeout:300000},async t=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-strict-service-'))),anchors=[];
 let epoch=0,session,replica;
 const wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:16},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3-unanimous',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network,authorityPin=config.witnesses[0].pin;
 const credentials=i=>({authorityPin:config.witnesses[i].pin,classicalPrivateKey:witnesses[i].cl.privateKey,pqPrivateKey:witnesses[i].pq.privateKey});
 const p=await port(),token=randomBytes(32).toString('hex'),replicaFile=join(dir,'replica.json'),keyFile=join(dir,'replica-key.pem'),pqKeyFile=join(dir,'replica-pq.pem'),quorumFile=join(dir,'quorum.json');
 const initial={format:'quantic-pay-external-checkpoint/v1',network,authorityPin,sequence:0,root:network,admission:null,financial:null};
 function freshSession(){
  return createCommitteeSession({network,authorityPin,provision:async request=>{
   const link=native?await startNativeScatteringLink({dir:join(dir,'epoch-'+(++epoch)),binary:resolve(process.env.QUANTIC_PAY_SCATTERING_TEST),relayPort:p,profile:request.profile==='vote'?'pay-committee-vote-lab':'pay-committee-recovery-lab'}):null;
   return {network,authorityPin,profile:request.profile,epochId:link?.epochId??randomBytes(32).toString('hex'),loopbackPort:link?Number(new URL(link.url).port):p,token,close:async()=>{await link?.close();}};
  }});
 }
 function checkpoints(){return anchors.map(a=>createPayAnchorClient({configFile:a.clientFile,network,authorityPin}).read());}
 try{
  writeFileSync(keyFile,witnesses[0].cl.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(pqKeyFile,witnesses[0].pq.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  privateJson(replicaFile,{simulationOnly:true,directory:join(dir,'replica'),chainConfig:config,expectedNetwork:network,authorityKeyFile:keyFile,authorityPin,authorityPQKeyFile:pqKeyFile,authorityPQPin:config.witnesses[0].pqPin,token,port:p});
  execFileSync(process.execPath,[replicaScript,'provision',replicaFile],{stdio:'ignore'});
  // Production-facing laboratory entry point cannot silently opt out.
  assert.throws(()=>execFileSync(process.execPath,[replicaScript,'serve',replicaFile],{stdio:'ignore',timeout:10000}));
  for(let i=0;i<4;i++){
   const serverFile=join(dir,'anchor-'+i+'.json'),clientFile=join(dir,'anchor-client-'+i+'.json'),keyFile=join(dir,'anchor-key-'+i+'.pem'),certFile=join(dir,'anchor-cert-'+i+'.pem'),portNumber=await port(),secret=randomBytes(32).toString('hex');
   execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',certFile,'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});chmodSync(keyFile,0o600);chmodSync(certFile,0o600);
   privateJson(serverFile,{simulationOnly:true,directory:join(dir,'anchor-'+i),initial,port:portNumber,token:secret,keyFile,certFile});
   privateJson(clientFile,{simulationOnly:true,network,authorityPin,port:portNumber,token:secret,certFile});
   execFileSync(process.execPath,[anchorScript,'provision',serverFile],{stdio:'ignore'});
   const a={clientFile,args:[anchorScript,'serve',serverFile],ready:'READY PAY ANCHOR LAB'};anchors.push(a);await start(a);
  }
  privateJson(quorumFile,{simulationOnly:true,network,authorityPin,members:anchors.map(a=>a.clientFile)});
  replica={args:[replicaScript,'serve-quorum-anchored',replicaFile,quorumFile],ready:'READY PAY REPLICA LAB'};
  await start(replica);session=freshSession();
  assert.equal((await session.status()).sequence,0);
  const now=Date.now(),intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}],admissionTime:now};
  const a=createPayRoundLab(lab.admissionRoundConfig([])),scope=a.scope,value=lab.draft([],draft).scope;
  assert.equal(a.committee.quorum,16);
  const others=Array.from({length:15},(_,i)=>a.openAuthority(credentials(i+1)));
  const remote=await session.admissionPrepare({scope,input:{draft,round:0}});
  const ap={scope,round:0,value,votes:[remote,...others.map(n=>n.prepare({round:0,value}))]};
  assert.throws(()=>a.prepared({...ap,votes:ap.votes.slice(0,15)}));
  const ac={scope,round:0,value,votes:[await session.admissionCommit({scope,input:{draft,certificate:ap}}),...others.map(n=>n.commit(ap))]};
  assert.throws(()=>a.finalized({prepared:ap,commit:{...ac,votes:ac.votes.slice(1)}}));
  const admission={...draft,admissionCertificate:{prepared:ap,commit:ac}},info=lab.admit([],admission);
  await session.admit(admission);
  t.diagnostic('strict admission installed, real elapsed ms='+String(Date.now()-now));
  const b=createPayRoundLab(info.config),fscope=b.scope,fvalue=info.candidates[0].value;
  const voters=Array.from({length:15},(_,i)=>b.openAuthority(credentials(i+1)));
  const fp={scope:fscope,round:0,value:fvalue,votes:[await session.prepare({scope:fscope,input:{round:0,value:fvalue}}),...voters.map(n=>n.prepare({round:0,value:fvalue}))]};
  assert.throws(()=>b.prepared({...fp,votes:fp.votes.slice(0,15)}));
  const fc={scope:fscope,round:0,value:fvalue,votes:[await session.commitVote({scope:fscope,input:fp}),...voters.map(n=>n.commit(fp))]};
  assert.throws(()=>b.finalized({prepared:fp,commit:{...fc,votes:fc.votes.slice(1)}}));
  const record={admission,certificate:{prepared:fp,commit:fc}},receipt=lab.receipt([],record);
  assert.deepEqual(await session.learn(record),receipt);
  const status=await session.status();assert.equal(status.sequence,1);assert.equal(status.root,receipt.root);assert.deepEqual(status.balances,{'demo-alice':2500,'demo-bob':7500});
  const retained=checkpoints();assert.equal(retained.length,4);
  for(const c of retained){assert.equal(c.sequence,1);assert.equal(c.root,receipt.root);assert.deepEqual(c,retained[0]);}
  t.diagnostic('16 hybrid signers, four external anchors retain one certified 75 EUR debit');
  // Lose one anchor only after all four have durably committed. Even a
  // read must refuse, and no new signature can be released.
  await stop(anchors[3]);
  await assert.rejects(session.status());assert.equal(session.sessionStatus().halted,true);session.close();
  await stop(replica);await start(anchors[3]);await start(replica);
  session=freshSession();assert.equal((await session.status()).root,receipt.root);
  assert.equal(session.sessionStatus().halted,false);session.close();
  t.diagnostic('3/4 outage blocks strict service; explicit restart after 4/4 restoration retains balance');
 }finally{
  if(session&&!session.sessionStatus().busy)session.close();
  await stop(replica);await Promise.all(anchors.map(stop));rmSync(dir,{recursive:true,force:true});
 }
});
