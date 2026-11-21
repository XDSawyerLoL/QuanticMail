// Windows native-v1 Pay operator with independently pinned configuration.
// The four configured loopback Pay carriers must already be provisioned.
// No production accounts, no automatic reset, no remote transport fallback.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,openSync,closeSync,fstatSync} from 'node:fs';
import {win32} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {parsePayOperatorConfig} from '../lib/quantic/pay-operator-config.mjs';
import {openNativePayRemoteFlow} from '../lib/quantic/pay-native-remote-flow.mjs';
import {payEuropeanReadiness} from '../lib/quantic/pay-eu-readiness.mjs';
import {formatDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
const check=v=>{if(!v)throw Error('Pay operator refused');};
const [binary,binPin,dir,configPin,mode,input]=process.argv.slice(2);
const pin=/^[a-f0-9]{64}$/;
check(process.platform==='win32'&&process.stdin.isTTY&&process.stdout.isTTY&&win32.isAbsolute(binary)&&win32.isAbsolute(dir)&&pin.test(binPin)&&pin.test(configPin));
check((mode==='run'&&process.argv.length===7)||(mode==='configure'&&process.argv.length===8&&win32.isAbsolute(input)));
const system=process.env.SystemRoot??process.env.SYSTEMROOT;check(typeof system==='string'&&win32.isAbsolute(system));
const env={SystemRoot:system,WINDIR:system,PATH:win32.dirname(binary)+';'+win32.join(system,'System32')};
function native(args,{data,limit=4*1024*1024,timeout=10000,interactive=false}={}){
 check(createHash('sha256').update(readFileSync(binary)).digest('hex')===binPin);
 if(process.stdin.isRaw)process.stdin.setRawMode(false);
 const r=spawnSync(binary,args,{cwd:win32.dirname(binary),env,shell:false,input:data,stdio:[data?'pipe':interactive?'inherit':'ignore','pipe','inherit'],maxBuffer:limit,timeout});
 check(r.status===0&&!r.error&&Buffer.isBuffer(r.stdout));return r.stdout;
}
async function ask(q){const rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});try{return (await rl.question(q)).trim();}finally{rl.close();}}
function history(){const b=native(['--read-windows-pay-history-lab',dir]);try{return JSON.parse(b.toString('utf8'));}finally{b.fill(0);}}
try{
 if(mode==='configure'){
  // The operator is responsible for protecting the source configuration and
  // disposing of it using the applicable custody procedure after import.
  const st=lstatSync(input);check(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=32768);
  const fd=openSync(input,'r');let raw;try{const a=fstatSync(fd);check(a.size===st.size);raw=readFileSync(fd);}finally{closeSync(fd);}
  try{parsePayOperatorConfig(raw,configPin);native(['--configure-windows-pay-quorum-lab',dir,configPin],{data:raw,interactive:true,limit:4096,timeout:120000});}finally{raw.fill(0);}
  console.log('Configuration de laboratoire conservee. Aucun paiement.');
 }else{
  const raw=native(['--read-windows-pay-quorum-lab',dir,configPin],{limit:32768});
  let c;try{c=parsePayOperatorConfig(raw,configPin);}finally{raw.fill(0);}
  const flow=await openNativePayRemoteFlow({...c,readHistory:history,signNative:async i=>{
   const b=native(['--sign-windows-pay-lab',dir,c.scope.signingPin,c.scope.pqPin,i.Payee,String(i.Cents),i.Nonce,String(i.Issued)],{interactive:true,limit:32768,timeout:115000});
   try{return JSON.parse(b.toString('utf8'));}finally{b.fill(0);}
  }});
  console.log('QUANTIC PAY / LABORATOIRE / COFFRE NATIF + 4 TEMOINS');
  console.log('Historique exact rapproche avec quorum. Aucun euro reel.');
  while(!flow.snapshot().halted){
   const s=flow.snapshot();console.log('Solde fictif '+formatDemoAmount(s.balanceCents)+' | preuves '+s.proofCount);
   const pick=await ask('1=commerce, 2=particulier, C=conformite, Q=quitter : ');
   if(pick.toLowerCase()==='q')break;
   if(pick.toLowerCase()==='c'){for(const row of payEuropeanReadiness().requirements)console.log(row.id+' '+row.status);continue;}
   if(!['1','2'].includes(pick))continue;
   const amount=await ask('Montant fictif : ');
   if(await ask('Taper SIMULER pour demander la validation native : ')!=='SIMULER')continue;
   try{const result=await flow.confirm({payeeId:pick==='1'?'demo-shop':'demo-person',amount,explicitConsent:true});console.log('Preuve '+result.nonce+' ; quorum '+result.witnessCount+'/4. Aucun reglement reel.');}
   catch{console.error('Operation refusee. Aucun nouvel essai automatique.');if(flow.snapshot().halted)break;}
  }
 }
}catch{console.error('Laboratoire refuse : verifier la configuration, les temoins et les recus. Aucun secret affiche.');process.exitCode=1;}
