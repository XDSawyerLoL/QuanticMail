// A new, dedicated native Pay vault per isolated local quorum experiment.
// No real payments; local in-memory witnesses are not independent operators.
// Never reopen or bootstrap a previously used vault into an empty witness set.
import {spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline/promises';
import {isAbsolute} from 'node:path';
import {createLocalWitnessFlow} from './quantic-pay-quorum-demo.mjs';
import {formatDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
const check=v=>{if(!v)throw Error('Native quorum laboratory refused');};
const pin=/^[a-f0-9]{64}$/;
const [binary,dir]=process.argv.slice(2);
check(process.platform==='win32'&&process.argv.length===4&&process.stdin.isTTY&&process.stdout.isTTY&&isAbsolute(binary)&&isAbsolute(dir));
async function ask(question){
 const rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});
 try{return (await rl.question(question)).trim()}finally{rl.close()}
}
function native(args){
 // No readline instance is active while the native console prompts.
 if(process.stdin.isRaw)process.stdin.setRawMode(false);
 const result=spawnSync(binary,args,{shell:false,stdio:['inherit','pipe','inherit'],encoding:'utf8',maxBuffer:32768});
 check(result.status===0&&!result.error);
 return JSON.parse(result.stdout);
}
console.log('QUANTIC PAY / COFFRE NATIF + QUORUM LOCAL / SIMULATION UNIQUEMENT');
console.log('Nouveau dossier obligatoire. Les temoins seront perdus a la fermeture.');
console.log('Ne jamais utiliser un coffre ou une identite de production.');
const created=native(['--provision-windows-pay-lab',dir]);
check(created?.mode==='fictional-pay-lab'&&created.status==='stored-not-enrolled'&&pin.test(created.signingPin)&&pin.test(created.pqPin));
const scope=Object.freeze({signingPin:created.signingPin,pqPin:created.pqPin});
console.log('Empreintes publiques du nouveau coffre : '+scope.signingPin+' / '+scope.pqPin);
const flow=createLocalWitnessFlow({scope,signProof:async i=>native(['--sign-windows-pay-lab',dir,scope.signingPin,scope.pqPin,i.Payee,String(i.Cents),i.Nonce,String(i.Issued)])});
while(!flow.snapshot().halted){
 console.log('Solde fictif : '+formatDemoAmount(flow.snapshot().balanceCents));
 const pick=await ask('1=commerce DEMO, 2=particulier DEMO, Q=quitter : ');
 if(pick.toLowerCase()==='q')break;
 if(!['1','2'].includes(pick))continue;
 const amount=await ask('Montant fictif : ');
 if((await ask('Taper SIMULER pour demander la validation native : '))!=='SIMULER')continue;
 try{
  const receipt=await flow.confirm({payeeId:pick==='1'?'demo-shop':'demo-person',amount,explicitConsent:true});
  console.log('Simulation confirmee : coffre natif + quorum '+receipt.witnessCount+'/4; '+receipt.proofCount+' preuve(s). Aucun reglement reel.');
 }catch{
  console.log('Simulation refusee. Aucun nouvel essai automatique.');
 }
}
console.log('Fin du laboratoire. Les preuves natives restent sur disque; les temoins locaux ne persistent pas. Ne pas reutiliser ce coffre dans ce parcours.');
