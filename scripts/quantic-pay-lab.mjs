import {createInterface} from 'node:readline/promises';
import {createPaySandbox,formatDemoAmount,PAYEES} from '../lib/quantic/pay-sandbox.mjs';
const engine=createPaySandbox();
if(process.argv.length===3&&process.argv[2]==='--self-test'){
 const p=engine.prepare({payeeId:PAYEES[0].id,amount:'12.50'});
 const receipt=engine.confirm(p.id);
 if(receipt.realPayment!==false||engine.snapshot().balanceCents!==8750)throw Error('Simulation incorrecte');
 console.log('Quantic Pay: simulation locale verifiee, aucun paiement reel.');
}else{
 if(process.argv.length!==2||!process.stdin.isTTY||!process.stdout.isTTY)throw Error('Terminal local interactif requis');
 const rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});
 try{
  console.log('QUANTIC PAY / LABORATOIRE - EUR FICTIFS / AUCUNE VALEUR MONETAIRE');
  while(true){
   const state=engine.snapshot();
   console.log('\nSolde fictif: '+formatDemoAmount(state.balanceCents));
   const choice=(await rl.question('1 = paiement fictif, 2 = historique, Q = quitter : ')).trim();
   if(choice.toLowerCase()==='q')break;
   if(choice==='2'){for(const x of state.history)console.log(x.id+' '+formatDemoAmount(x.cents)+' '+x.status+' / SIMULATION');continue;}
   if(choice!=='1')continue;
   try{
    const p=(await rl.question('1 = commerce DEMO, 2 = particulier DEMO : ')).trim();
    if(!['1','2'].includes(p))continue;
    const amount=(await rl.question('Montant fictif : ')).trim();
    const intent=engine.prepare({payeeId:PAYEES[Number(p)-1].id,amount});
    console.log('Destinataire : '+PAYEES[Number(p)-1].label+' / '+formatDemoAmount(intent.cents)+' / '+intent.id);
    const confirm=(await rl.question('Taper SIMULER pour confirmer, autre saisie pour annuler : ')).trim();
    const result=confirm==='SIMULER'?engine.confirm(intent.id):engine.cancel(intent.id);
    console.log('Resultat fictif : '+result.status+', aucun transfert reel.');
   }catch(e){console.log(e instanceof Error?e.message:'Operation refusee.');}
  }
 }finally{rl.close();}
}
