import {createInterface} from 'node:readline/promises';
import {createCirculationSession,DEMO_WALLETS} from '../lib/quantic/pay-circulation-session.mjs';
import {formatDemoAmount,parseDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
import {payEuropeanReadiness} from '../lib/quantic/pay-eu-readiness.mjs';
const session=createCirculationSession();
function transfer(payer,payee,cents){const p=session.prepare({payer,payee,cents});return session.confirm({nonce:p.nonce,explicitConsent:true});}
if(process.argv.length===3&&process.argv[2]==='--self-test'){
 transfer('demo-alice','demo-bob',7500);
 session.setAvailability([0,1,2]);
 const second=transfer('demo-bob','demo-shop',7000);
 session.setAvailability([0,1]);
 let refused=false;try{transfer('demo-shop','demo-alice',6000);}catch{refused=true;}
 if(!refused||session.snapshot().sequence!==2||second.witnessCount!==3)throw Error('Quorum refusal failed');
 session.setAvailability([0,1,2,3]);
 transfer('demo-shop','demo-alice',6000);
 const s=session.snapshot();
 if(s.balances['demo-alice']!==8500||s.balances['demo-bob']!==500||s.balances['demo-shop']!==1000||s.totalCents!==10000||session.history().length!==3)throw Error('Circulation self-test failed');
 console.log('Pay circulation laboratory: three signed transfers, quorum refusal and conserved value verified; no real money.');
}else{
 if(process.argv.length!==2||!process.stdin.isTTY||!process.stdout.isTTY)throw Error('Interactive circulation laboratory only');
 const rl=createInterface({input:process.stdin,output:process.stdout,terminal:true,historySize:0});
 const ask=async q=>(await rl.question(q)).trim();
 try{
  console.log('QUANTIC PAY / CIRCULATION FICTIVE / SESSION NON PERSISTANTE');
  console.log('Cles de demonstration locales uniquement. Ni coffre reel, ni PSP, ni connexion distante.');
  while(!session.snapshot().blocked){
   const s=session.snapshot();
   for(const [i,id] of DEMO_WALLETS.entries())console.log((i+1)+' '+id+' : '+formatDemoAmount(s.balances[id]));
   console.log('Temoins simulés disponibles : '+s.availableWitnesses+'/4 | Total : '+formatDemoAmount(s.totalCents));
   const op=await ask('P=transfert, H=historique, T=test disponibilite, C=conformite, Q=quitter : ');
   if(op.toUpperCase()==='Q')break;
   if(op.toUpperCase()==='H'){for(const x of session.history())console.log(x.reference+' '+x.payer+' -> '+x.payee+' '+formatDemoAmount(x.cents));continue;}
   if(op.toUpperCase()==='C'){for(const row of payEuropeanReadiness().requirements)console.log(row.id+' '+row.requirement+' : '+row.status);continue;}
   if(op.toUpperCase()==='T'){const n=await ask('Nombre de temoins disponibles (2,3,4) : ');if(['2','3','4'].includes(n))session.setAvailability(Array.from({length:Number(n)},(_,i)=>i));continue;}
   if(op.toUpperCase()!=='P')continue;
   try{
    const from=await ask('Payeur (1,2,3) : '),to=await ask('Destinataire (1,2,3) : ');
    if(!['1','2','3'].includes(from)||!['1','2','3'].includes(to))continue;
    const cents=parseDemoAmount(await ask('Montant fictif : '));
    const intent=session.prepare({payer:DEMO_WALLETS[Number(from)-1],payee:DEMO_WALLETS[Number(to)-1],cents});
    console.log(intent.payer+' -> '+intent.payee+' : '+formatDemoAmount(intent.cents));
    if(await ask('Taper SIMULER pour confirmer cette operation fictive : ')!=='SIMULER'){session.cancel(intent.nonce);continue;}
    const r=session.confirm({nonce:intent.nonce,explicitConsent:true});console.log(r.reference+' | quorum '+r.witnessCount+'/4 | aucune valeur monetaire.');
   }catch{console.log('Operation refusee. Aucun nouvel essai automatique.');}
  }
 }finally{rl.close();}
}
