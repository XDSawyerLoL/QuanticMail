// Explicitly fictional, single-transfer demonstration; no persistent wallet,
// account credentials, network or production settlement.
import {createCirculationSession} from '../lib/quantic/pay-circulation-session.mjs';
import {parseDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
import {pathToFileURL} from 'node:url';

export function simulateDesktopPay(req){
 if(!req||Object.getPrototypeOf(req)!==Object.prototype||
    Object.keys(req).sort().join(',')!=='amount,consent,payee,witnesses'||
    req.consent!==true||!['demo-bob','demo-shop'].includes(req.payee)||
    ![2,3,4].includes(req.witnesses))throw Error('Invalid demonstration');
 const cents=parseDemoAmount(req.amount);
 const session=createCirculationSession();
 session.setAvailability(Array.from({length:req.witnesses},(_,i)=>i));
 if(req.witnesses<3)return {mode:'simulation',status:'refused',realPaymentAuthorized:false,witnesses:req.witnesses,cents,balanceCents:session.snapshot().balances['demo-alice']};
 const intent=session.prepare({payer:'demo-alice',payee:req.payee,cents});
 const result=session.confirm({nonce:intent.nonce,explicitConsent:true});
 if(result.realPaymentAuthorized!==false||result.simulationOnly!==true||result.settlementVerified!==false)throw Error('Unexpected payment result');
 return {mode:'simulation',status:'confirmed',realPaymentAuthorized:false,witnesses:result.witnessCount,cents:result.cents,balanceCents:session.snapshot().balances['demo-alice'],reference:result.reference};
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 try{
  if(process.argv.length!==2)throw Error('No arguments');
  const chunks=[];let n=0;
  for await(const chunk of process.stdin){n+=chunk.length;if(n>4096)throw Error('Input too large');chunks.push(chunk)}
  process.stdout.write(JSON.stringify(simulateDesktopPay(JSON.parse(Buffer.concat(chunks).toString('utf8')))));
 }catch{process.exitCode=2;}
}
