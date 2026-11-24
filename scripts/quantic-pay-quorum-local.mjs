import {createLocalQuorumDemo} from './quantic-pay-quorum-demo.mjs';
import {createInterface} from 'node:readline/promises';
import {formatDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
const flow=createLocalQuorumDemo();
if(process.argv.length===3&&process.argv[2]==='--self-test'){
 const r=await flow.confirm({payeeId:'demo-shop',amount:'2.50',explicitConsent:true});
 if(r.balanceCents!==9750||r.witnessCount!==4||r.realPaymentAuthorized!==false)throw Error('Pay quorum simulation failed');
 console.log('Pay laboratory: signed before/after quorum confirmed; no real money.');
}else{
 if(process.argv.length!==2||!process.stdin.isTTY||!process.stdout.isTTY)throw Error('Interactive laboratory only');
 const rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});
 try{
  console.log('QUANTIC PAY / QUORUM LOCAL EN MEMOIRE / AUCUN ARGENT REEL');
  while(!flow.snapshot().halted){
   console.log('Solde fictif : '+formatDemoAmount(flow.snapshot().balanceCents));
   const amount=(await rl.question('Montant fictif vers commerce DEMO (Q pour quitter) : ')).trim();
   if(amount.toLowerCase()==='q')break;
   if((await rl.question('Taper SIMULER pour confirmer '+amount+' EUR fictifs : ')).trim()!=='SIMULER')continue;
   try{const r=await flow.confirm({payeeId:'demo-shop',amount,explicitConsent:true});console.log('Simulation : '+r.witnessCount+'/4 temoins, '+r.proofCount+' preuves. Aucun reglement reel.');}
   catch{console.log('Simulation refusee. Etat incertain : session bloquee, aucun nouvel essai automatique.');}
  }
 }finally{rl.close()}
}
