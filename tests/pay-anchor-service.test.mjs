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
const script=fileURLToPath(new URL('../scripts/serve-pay-anchor-lab.mjs',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const spki=k=>k.publicKey.export({format:'der',type:'spki'});
const pair=type=>({cl:type==='ec'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):generateKeyPairSync(type),pq:generateKeyPairSync('ml-dsa-65')});
const pub=k=>({pin:sha(spki(k.cl)),publicKey:spki(k.cl).toString('base64url'),pqPin:sha(spki(k.pq)),pqPublicKey:spki(k.pq).toString('base64url')});
async function port(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function restore(src,dst){cpSync(src,dst,{recursive:true});function fix(p){chmodSync(p,0o700);for(const e of readdirSync(p,{withFileTypes:true})){const q=join(p,e.name);if(e.isDirectory())fix(q);else chmodSync(q,0o600);}}fix(dst);}
test('separate durable TLS anchor refuses stale CAS, replica rollback and unavailable service',{skip:process.platform!=='linux',timeout:60000},async()=>{
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'pay-anchor-'))),wallets=[pair('ec'),pair('ec')],witnesses=Array.from({length:4},()=>pair('ed25519'));
 const config={admissionPolicy:'round-v3',wallets:wallets.map((w,i)=>({id:i?'demo-bob':'demo-alice',initialCents:i?0:10000,...pub(w)})),witnesses:witnesses.map(pub)};
 const lab=createRoundCirculationLab(config),network=lab.snapshot([]).network,authorityPin=config.witnesses[0].pin,now=1000000;
 const opts={directory:join(dir,'replica'),config,authorityPin,classicalPrivateKey:witnesses[0].cl.privateKey,pqPrivateKey:witnesses[0].pq.privateKey,clock:()=>now};
 const serverFile=join(dir,'anchor.json'),clientFile=join(dir,'client.json'),keyFile=join(dir,'key.pem'),certFile=join(dir,'cert.pem'),p=await port(),token=randomBytes(32).toString('hex');
 let node,proc;
 async function start(){
  proc=spawn(process.execPath,[script,'serve',serverFile],{stdio:['ignore','pipe','pipe']});
  await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('anchor startup timeout')),10000);proc.once('error',e=>{clearTimeout(timer);rej(e);});proc.once('exit',()=>{clearTimeout(timer);rej(Error('anchor stopped'));});proc.stdout.on('data',b=>{if(b.toString().includes('READY PAY ANCHOR LAB')){clearTimeout(timer);res();}});proc.stderr.resume();});
 }
 async function stop(){if(proc&&proc.exitCode===null&&proc.signalCode===null)await new Promise(r=>{proc.once('exit',r);proc.kill();});}
 try{
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',certFile,'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});chmodSync(keyFile,0o600);chmodSync(certFile,0o600);
  node=openPayRoundReplica({...opts,createNew:true});const initial=node.checkpoint();node.close();restore(opts.directory,join(dir,'backup'));
  writeFileSync(serverFile,JSON.stringify({simulationOnly:true,directory:join(dir,'anchor'),initial,port:p,token,keyFile,certFile}),{mode:0o600,flag:'wx'});
  writeFileSync(clientFile,JSON.stringify({simulationOnly:true,network,authorityPin,port:p,token,certFile}),{mode:0o600,flag:'wx'});
  execFileSync(process.execPath,[script,'provision',serverFile],{stdio:'ignore'});await start();
  const anchor=createPayAnchorClient({configFile:clientFile,network,authorityPin});
  assert.deepEqual(anchor.read(),initial);
  node=openAnchoredPayReplica({...opts,anchor});
  const intent=lab.prepare([],{payer:'demo-alice',payee:'demo-bob',cents:7500,nonce:randomBytes(32).toString('hex'),now}),raw=lab.transcript(intent);
  const draft={admissionTime:now,proposals:[{intent,signature:sign('sha256',raw,{key:wallets[0].cl.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url'),pqSignature:sign(null,raw,wallets[0].pq.privateKey).toString('base64url')}]};
  const scope=createPayRoundLab(lab.admissionRoundConfig([])).scope;
  const vote=node.admissionPrepare({scope,input:{draft,round:0}});assert.equal(vote.pin,authorityPin);
  const latest=anchor.read();assert.equal(latest.admission.count,1);
  assert.throws(()=>anchor.compareAndSwap(initial,initial));assert.throws(()=>anchor.compareAndSwap(latest,initial));
  node.close();await stop();await start();assert.deepEqual(anchor.read(),latest);
  node=openAnchoredPayReplica({...opts,anchor});
  await stop();assert.throws(()=>node.admissionChange({scope,input:1}),/halted/);assert.equal(node.anchorStatus().halted,true);node.close();
  await start();assert.deepEqual(anchor.read(),latest);
  node=openAnchoredPayReplica({...opts,anchor});node.close();
  rmSync(opts.directory,{recursive:true,force:true});restore(join(dir,'backup'),opts.directory);
  assert.throws(()=>openAnchoredPayReplica({...opts,anchor}),/checkpoint mismatch/);
 }finally{node?.close();await stop();rmSync(dir,{recursive:true,force:true});}
});
